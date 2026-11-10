terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 5.12"
    }
    tls    = { source = "hashicorp/tls" }
    random = { source = "hashicorp/random" }
  }

  # azurerm keeps each VM's first admin password and the extensions' settings
  # in state, and those settings hold the hosts' private keys. Keep state
  # encrypted.
  encryption {
    key_provider "pbkdf2" "state" {
      passphrase = var.state_passphrase
    }
    method "aes_gcm" "state" {
      keys = key_provider.pbkdf2.state
    }
    state {
      method = method.aes_gcm.state
    }
    plan {
      method = method.aes_gcm.state
    }
  }
}

provider "azurerm" {
  features {}
}

variable "state_passphrase" {
  type        = string
  sensitive   = true
  description = "Encrypts state and saved plans. At least 16 characters."
}

variable "admin_cidrs" {
  type        = list(string)
  description = "Who may reach SSH, such as [\"203.0.113.7/32\"]. Nothing else gets in."
}

variable "admin_public_key_file" {
  type        = string
  description = "Your SSH public key, which logs in as azadmin on every VM."
}

variable "admin_private_key_file" {
  type        = string
  description = "The private half, which Conn3x logs in with."
}

variable "dsrm_password" {
  type        = string
  ephemeral   = true
  description = "Directory Services Restore Mode password for both domain controllers. Never in plan or state."
}

variable "user_passwords" {
  type        = map(string)
  ephemeral   = true
  description = "Passwords for the lab's users, alice and bob, such as {alice = \"...\", bob = \"...\"}. Never in plan or state."
}

variable "name" {
  type        = string
  default     = "conn3x-ad-lab"
  description = "Name of the resource group, and the start of everything in it."
}

variable "location" {
  type    = string
  default = "westus2"
}

variable "size" {
  type    = string
  default = "Standard_B2s_v2"
}

variable "tags" {
  type    = map(string)
  default = {}
}

locals {
  domain = "lab.conn3x.test"
  # Fixed addresses, so DNS can name the domain controllers.
  vms = { dc1 = "10.46.0.4", dc2 = "10.46.0.5", srv1 = "10.46.0.6", srv2 = "10.46.0.7" }
  dcs = ["dc1", "dc2"]

  hosts = { for k, ip in local.vms : k => {
    address    = azurerm_public_ip.this[k].ip_address
    host_key   = tls_private_key.host[k].public_key_openssh
    private_ip = ip
  } }
}

# Each host's SSH key, made here and installed at first boot, so Conn3x can
# check each host from the first connection.
resource "tls_private_key" "host" {
  for_each  = local.vms
  algorithm = "ED25519"
}

# Azure insists on a password for each VM. Steps below replace them.
resource "random_password" "first_admin" {
  for_each    = local.vms
  length      = 32
  min_lower   = 1
  min_upper   = 1
  min_numeric = 1
  min_special = 1
}

resource "azurerm_resource_group" "this" {
  name     = var.name
  location = var.location
  tags     = var.tags
}

resource "azurerm_virtual_network" "this" {
  name                = "${var.name}-net"
  location            = azurerm_resource_group.this.location
  resource_group_name = azurerm_resource_group.this.name
  address_space       = ["10.46.0.0/16"]
  tags                = var.tags
}

resource "azurerm_subnet" "this" {
  name                 = "hosts"
  resource_group_name  = azurerm_resource_group.this.name
  virtual_network_name = azurerm_virtual_network.this.name
  address_prefixes     = ["10.46.0.0/24"]
}

# The VMs reach each other inside the network, as Azure allows by default.
# From outside, only SSH from admin_cidrs.
resource "azurerm_network_security_group" "this" {
  name                = "${var.name}-nsg"
  location            = azurerm_resource_group.this.location
  resource_group_name = azurerm_resource_group.this.name
  tags                = var.tags

  security_rule {
    name                       = "ssh-from-admins"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefixes    = var.admin_cidrs
    destination_address_prefix = "*"
  }
}

resource "azurerm_subnet_network_security_group_association" "this" {
  subnet_id                 = azurerm_subnet.this.id
  network_security_group_id = azurerm_network_security_group.this.id
}

resource "azurerm_public_ip" "this" {
  for_each            = local.vms
  name                = "${var.name}-${each.key}-ip"
  location            = azurerm_resource_group.this.location
  resource_group_name = azurerm_resource_group.this.name
  allocation_method   = "Static"
  sku                 = "Standard"
  tags                = var.tags
}

resource "azurerm_network_interface" "this" {
  for_each            = local.vms
  name                = "${var.name}-${each.key}-nic"
  location            = azurerm_resource_group.this.location
  resource_group_name = azurerm_resource_group.this.name
  tags                = var.tags

  ip_configuration {
    name                          = "main"
    subnet_id                     = azurerm_subnet.this.id
    private_ip_address_allocation = "Static"
    private_ip_address            = each.value
    public_ip_address_id          = azurerm_public_ip.this[each.key].id
  }
}

resource "azurerm_windows_virtual_machine" "this" {
  for_each                  = local.vms
  name                      = each.key
  location                  = azurerm_resource_group.this.location
  resource_group_name       = azurerm_resource_group.this.name
  size                      = var.size
  admin_username            = "azadmin"
  admin_password            = random_password.first_admin[each.key].result
  network_interface_ids     = [azurerm_network_interface.this[each.key].id]
  patch_mode                = "Manual"
  automatic_updates_enabled = false
  tags                      = var.tags

  # Windows doesn't run this by itself. The extension below does. It holds only
  # public keys, as anyone who can read the VM's settings can read it.
  custom_data = base64encode(replace(replace(file("${path.module}/bootstrap.ps1"),
    "__HOST_PUB__", trimspace(tls_private_key.host[each.key].public_key_openssh)),
  "__ADMIN_PUB__", trimspace(file(var.admin_public_key_file))))

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "StandardSSD_LRS"
  }

  # The -g2 image is the Generation 2 one. Plain 2025-datacenter is Generation 1.
  source_image_reference {
    publisher = "MicrosoftWindowsServer"
    offer     = "WindowsServer"
    sku       = "2025-datacenter-g2"
    version   = "latest"
  }
}

resource "azurerm_virtual_machine_extension" "bootstrap" {
  for_each             = local.vms
  name                 = "bootstrap"
  virtual_machine_id   = azurerm_windows_virtual_machine.this[each.key].id
  publisher            = "Microsoft.Compute"
  type                 = "CustomScriptExtension"
  type_handler_version = "1.10"

  # Extra settings stay encrypted beside the command, which an audit policy could
  # record. Only bootstrap.ps1 opens them: the key is on no command line. The
  # script runs straight from where Azure put it; a copy in a shared folder such
  # as C:\Windows\Temp is a name any local user could have created first.
  protected_settings = jsonencode({
    commandToExecute = "powershell.exe -NoProfile -ExecutionPolicy Bypass -Command \"& ([scriptblock]::Create([IO.File]::ReadAllText('C:\\AzureData\\CustomData.bin')))\""
    conn3xHostKey    = base64encode(tls_private_key.host[each.key].private_key_openssh)
  })
}

# The whole domain: dc1 makes the forest, dc2 joins and becomes the second
# DC, srv1 and srv2 join as members, and dc1 fills the directory.
module "ad" {
  # v0.1.1, by commit: this circuit is handed the domain admin's password, and
  # a commit can't be moved the way a tag can.
  source = "github.com/conn3xorg/circuit-active-directory?ref=cbfa028e778091203796680bbbd6903aaa77f6c8"

  # Nothing connects until the extensions have installed the host keys.
  depends_on = [azurerm_virtual_machine_extension.bootstrap]

  domain_name        = local.domain
  netbios_name       = "LAB"
  domain_controllers = { for k in local.dcs : k => local.hosts[k] }
  members            = { for k, h in local.hosts : k => h if !contains(local.dcs, k) }

  ssh_user             = "azadmin"
  ssh_private_key_file = var.admin_private_key_file
  safe_mode_password   = var.dsrm_password

  # Promotion makes dc1's admin the domain's LAB\azadmin, with the password
  # Azure needed, which state holds anyway. The others join with it, and the
  # last steps below replace it.
  domain_admin_password = random_password.first_admin["dc1"].result

  ous = {
    Lab     = { description = "Made by Conn3x" }
    Servers = { path = "OU=Lab", description = "Member servers" }
    People  = { path = "OU=Lab" }
  }
  member_ou = "OU=Servers,OU=Lab"

  users = {
    alice = { path = "OU=People,OU=Lab", given_name = "Alice", surname = "Example", display_name = "Alice Example" }
    bob   = { path = "OU=People,OU=Lab", given_name = "Bob", surname = "Example", display_name = "Bob Example" }
  }
  user_passwords = var.user_passwords

  groups = {
    LabAdmins = { path = "OU=Lab", description = "Can manage the lab", members = ["alice"] }
    Helpdesk  = { path = "OU=Lab", description = "Resets passwords", members = ["alice", "bob"] }
  }
}

# Now nobody knows the domain admin's first password. Key login keeps working.
circuit "dc_password" {
  hosts = { dc1 = local.hosts.dc1 }

  ssh {
    user             = "azadmin"
    private_key_file = var.admin_private_key_file
    become           = true
    timeout          = "15m"
  }

  step "forget_first_password" {
    depends_on = [module.ad]

    windows_powershell {
      script = <<-PS
        $bytes = New-Object byte[] 48
        [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
        $p = (New-Object Net.NetworkCredential('', ('Aa1!' + [Convert]::ToBase64String($bytes)))).SecurePassword
        Import-Module ActiveDirectory
        Set-ADAccountPassword -Identity azadmin -Reset -NewPassword $p
        Set-ADUser -Identity azadmin -Description 'First password replaced by Conn3x'
      PS
      unless = "Import-Module ActiveDirectory; (Get-ADUser azadmin -Properties Description).Description -eq 'First password replaced by Conn3x'"
    }
  }
}

# The same for each member's local azadmin. dc2 has no local accounts.
circuit "member_passwords" {
  hosts = { for k, h in local.hosts : k => h if !contains(local.dcs, k) }

  ssh {
    user             = "azadmin"
    private_key_file = var.admin_private_key_file
    become           = true
    timeout          = "15m"
  }

  step "forget_first_password" {
    depends_on = [module.ad]

    windows_powershell {
      script = <<-PS
        $bytes = New-Object byte[] 48
        [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
        $p = (New-Object Net.NetworkCredential('', ('Aa1!' + [Convert]::ToBase64String($bytes)))).SecurePassword
        Set-LocalUser -Name azadmin -Password $p -Description 'First password replaced by Conn3x'
      PS
      unless = "(Get-LocalUser azadmin).Description -eq 'First password replaced by Conn3x'"
    }
  }
}

output "ips" {
  value = { for k, ip in azurerm_public_ip.this : k => ip.ip_address }
}

output "ssh_commands" {
  value = { for k, ip in azurerm_public_ip.this : k => "ssh azadmin@${ip.ip_address}" }
}

output "host_keys" {
  value = { for k, key in tls_private_key.host : k => key.public_key_openssh }
}
