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

variable "name" {
  type        = string
  default     = "conn3x-ad-child-domain"
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
  root  = "lab.conn3x.test"
  child = "emea.${local.root}"
  # Fixed addresses, so DNS can name the domain controllers.
  vms = { dc1 = "10.46.0.4", dc2 = "10.46.0.5" }

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
  # record. Only bootstrap.ps1 opens them: the key is on no command line.
  protected_settings = jsonencode({
    commandToExecute = "powershell.exe -NoProfile -ExecutionPolicy Bypass -Command Copy-Item C:\\AzureData\\CustomData.bin C:\\Windows\\Temp\\bootstrap.ps1 -Force; C:\\Windows\\Temp\\bootstrap.ps1"
    conn3xHostKey    = base64encode(tls_private_key.host[each.key].private_key_openssh)
  })
}

# sshd answers before AD does, and ADWS on 9389 before Get-ADDomain works.
# The AD steps wait for the global catalog themselves.

# dc1 makes the forest and is its DNS server.
circuit "root" {
  hosts = { dc1 = local.hosts.dc1 }

  # The bare name keeps working after promotion, as the domain's account.
  ssh {
    user             = "azadmin"
    private_key_file = var.admin_private_key_file
    become           = true
    timeout          = "15m"
  }

  step "ad_ds" {
    # Nothing connects until the extension has installed the host key.
    depends_on = [azurerm_virtual_machine_extension.bootstrap]

    windows_feature {
      name                     = "AD-Domain-Services"
      include_management_tools = true
    }
  }

  step "forest" {
    windows_ad_forest {
      domain_name           = local.root
      netbios_name          = "LAB"
      safe_mode_password_wo = var.dsrm_password
    }
  }

  step "promoted" {
    windows_reboot {
      only_if_pending = true
      timeout         = "15m"
    }
  }

  step "adws" {
    windows_wait_for {
      port    = 9389
      timeout = "10m"
    }
  }

  # Itself first, then loopback, as for any DC.
  step "dns" {
    windows_dns_client {
      servers = [local.vms.dc1, "127.0.0.1"]
    }
  }
}

# dc2 becomes the first domain controller of emea.lab.conn3x.test, a child
# of the forest root.
circuit "child" {
  hosts = { dc2 = local.hosts.dc2 }

  ssh {
    user             = "azadmin"
    private_key_file = var.admin_private_key_file
    become           = true
    timeout          = "15m"
  }

  # AD DS goes on while the forest is still being made.
  step "ad_ds" {
    depends_on = [azurerm_virtual_machine_extension.bootstrap]

    windows_feature {
      name                     = "AD-Domain-Services"
      include_management_tools = true
    }
  }

  # The new domain has to find its parent, so dc1 first. Promotion adds
  # loopback itself, so it's here from the start.
  step "dns" {
    depends_on = [conn3x_windows_dns_client.root__dns]

    windows_dns_client {
      servers = [local.vms.dc1, "127.0.0.1"]
    }
  }

  # Making the forest made dc1's admin the forest root's azadmin, an
  # Enterprise Admin, with the password Azure needed, which state holds
  # anyway. The last steps below replace it. Promotion finds the forest
  # through DNS, so the account is named by the domain's DNS name.
  step "domain" {
    windows_ad_domain {
      domain_name           = local.child
      netbios_name          = "EMEA"
      username              = "azadmin@${local.root}"
      password_wo           = random_password.first_admin["dc1"].result
      safe_mode_password_wo = var.dsrm_password
    }
  }

  step "promoted" {
    windows_reboot {
      only_if_pending = true
      timeout         = "15m"
    }
  }

  step "adws" {
    windows_wait_for {
      port    = 9389
      timeout = "10m"
    }
  }
}

# Now nobody knows either domain admin's first password. Key login keeps
# working: on each DC the bare azadmin is that domain's account.
circuit "passwords" {
  hosts = { for k in keys(local.vms) : k => local.hosts[k] }

  ssh {
    user             = "azadmin"
    private_key_file = var.admin_private_key_file
    become           = true
    timeout          = "15m"
  }

  step "forget_first_password" {
    depends_on = [conn3x_windows_wait_for.child__adws]

    windows_powershell {
      script = <<-PS
        $bytes = New-Object byte[] 48
        [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
        $p = (New-Object Net.NetworkCredential('', ('Aa1!' + [Convert]::ToBase64String($bytes)))).SecurePassword
        Import-Module ActiveDirectory
        Set-ADAccountPassword -Server localhost -Identity azadmin -Reset -NewPassword $p
        Set-ADUser -Server localhost -Identity azadmin -Description 'First password replaced by Conn3x'
      PS
      unless = "Import-Module ActiveDirectory; (Get-ADUser -Server localhost azadmin -Properties Description).Description -eq 'First password replaced by Conn3x'"
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
