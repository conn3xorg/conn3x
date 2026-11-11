terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 5.12"
    }
    tls    = { source = "hashicorp/tls" }
    random = { source = "hashicorp/random" }
  }

  # azurerm keeps the first admin password and the extension's settings in
  # state, and those settings hold the host's private key. Keep state encrypted.
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
  description = "Your SSH public key, which logs in as azadmin."
}

variable "admin_private_key_file" {
  type        = string
  description = "The private half, which Conn3x logs in with."
}

variable "name" {
  type        = string
  default     = "conn3x-windows-example"
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

variable "app_secret" {
  type        = string
  ephemeral   = true
  description = "Written to the host, and never to the plan or state."
}

# The host's SSH key, made here and installed at first boot, so Conn3x can check
# the host from the first connection. Conn3x installs its own host key.
resource "tls_private_key" "host" {
  algorithm = "ED25519"
}

# Azure insists on a password. The last step below replaces it.
resource "random_password" "first_admin" {
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
  address_space       = ["10.44.0.0/16"]
  tags                = var.tags
}

resource "azurerm_subnet" "this" {
  name                 = "hosts"
  resource_group_name  = azurerm_resource_group.this.name
  virtual_network_name = azurerm_virtual_network.this.name
  address_prefixes     = ["10.44.0.0/24"]
}

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
  name                = "${var.name}-ip"
  location            = azurerm_resource_group.this.location
  resource_group_name = azurerm_resource_group.this.name
  allocation_method   = "Static"
  sku                 = "Standard"
  tags                = var.tags
}

resource "azurerm_network_interface" "this" {
  name                = "${var.name}-nic"
  location            = azurerm_resource_group.this.location
  resource_group_name = azurerm_resource_group.this.name
  tags                = var.tags

  ip_configuration {
    name                          = "main"
    subnet_id                     = azurerm_subnet.this.id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = azurerm_public_ip.this.id
  }
}

resource "azurerm_windows_virtual_machine" "this" {
  name                      = "win1"
  location                  = azurerm_resource_group.this.location
  resource_group_name       = azurerm_resource_group.this.name
  size                      = var.size
  admin_username            = "azadmin"
  admin_password            = random_password.first_admin.result
  network_interface_ids     = [azurerm_network_interface.this.id]
  patch_mode                = "Manual"
  automatic_updates_enabled = false
  tags                      = var.tags

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
  name                 = "bootstrap"
  virtual_machine_id   = azurerm_windows_virtual_machine.this.id
  publisher            = "Microsoft.Compute"
  type                 = "CustomScriptExtension"
  type_handler_version = "1.10"

  # Only SYSTEM can decrypt protected settings. The command runs
  # load-bootstrap.ps1, which opens them and runs bootstrap.ps1 from there: the
  # script is never a file on the VM that someone else could change before it
  # runs, and the host's private key is on no command line.
  protected_settings = jsonencode({
    commandToExecute = "powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand ${textencodebase64(file("${path.module}/load-bootstrap.ps1"), "UTF-16LE")}"
    conn3xBootstrap = base64encode(replace(replace(file("${path.module}/bootstrap.ps1"),
      "__HOST_PUB__", trimspace(tls_private_key.host.public_key_openssh)),
    "__ADMIN_PUB__", trimspace(file(var.admin_public_key_file))))
    conn3xHostKey = base64encode(tls_private_key.host.private_key_openssh)
  })
}

circuit "windows" {
  hosts = {
    win1 = {
      address  = azurerm_public_ip.this.ip_address
      host_key = tls_private_key.host.public_key_openssh
    }
  }

  ssh {
    user             = "azadmin"
    private_key_file = var.admin_private_key_file
    become           = true
    timeout          = "15m"
  }

  # Nothing connects until the extension has installed the host key.
  step "web_server" {
    depends_on = [azurerm_virtual_machine_extension.bootstrap]

    windows_feature {
      name                     = "Web-Server"
      include_management_tools = true
    }
  }

  step "restart_if_needed" {
    windows_reboot {
      only_if_pending = true
    }
  }

  step "web_running" {
    windows_service {
      name       = "W3SVC"
      start_mode = "auto"
      state      = "running"
    }
  }

  step "long_paths" {
    windows_registry_value {
      key  = "HKLM\\SYSTEM\\CurrentControlSet\\Control\\FileSystem"
      name = "LongPathsEnabled"
      type = "dword"
      data = "1"
    }
  }

  # Its own rules, from the moment it exists: on this image, every signed-in
  # user could otherwise change a new folder at the top of the drive.
  step "app_dir" {
    windows_directory {
      path = "C:\\app"

      acl {
        principal = "S-1-5-18"
        rights    = ["FullControl"]
      }
      acl {
        principal = "S-1-5-32-544"
        rights    = ["FullControl"]
      }
      acl {
        principal = "S-1-5-32-545"
        rights    = ["ReadAndExecute"]
      }
    }
  }

  step "config" {
    windows_file {
      path    = "C:\\app\\config.json"
      content = jsonencode({ greeting = "set up by Conn3x" })
    }
  }

  # Readable by SYSTEM and Administrators only.
  step "secret" {
    windows_file {
      path       = "C:\\app\\secret.txt"
      content_wo = var.app_secret
    }
  }

  step "logs" {
    windows_directory {
      path = "C:\\app\\logs"
    }
  }

  # A few added rules go on a path whose whole list nothing else manages.
  step "network_service_can_read" {
    windows_acl {
      path = "C:\\app\\logs"

      entry {
        principal = "S-1-5-20"
        rights    = ["Read"]
      }
    }
  }

  # Replaces the password Azure needed, which state still holds, with one nobody
  # knows. Key login keeps working. Don't disable the account: that ends it.
  step "forget_first_password" {
    windows_powershell {
      script  = <<-PS
        param($A)
        $bytes = New-Object byte[] 48
        [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
        $p = (New-Object Net.NetworkCredential('', ('Aa1!' + [Convert]::ToBase64String($bytes)))).SecurePassword
        Set-LocalUser -Name azadmin -Password $p
        [IO.File]::WriteAllText($A.marker, 'done')
      PS
      args    = { marker = "C:\\app\\first-password-gone" }
      creates = "C:\\app\\first-password-gone"
    }
  }
}

output "ip" {
  value = azurerm_public_ip.this.ip_address
}

output "ssh_command" {
  value = "ssh azadmin@${azurerm_public_ip.this.ip_address}"
}

output "host_key" {
  value = tls_private_key.host.public_key_openssh
}
