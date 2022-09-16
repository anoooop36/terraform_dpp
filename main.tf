#Directory = /terraform-usecases/test::main
#File1 = main.tf
#File2 = output.tf
#File3 = provider.tf
#File4 = variables.tf
#File5 = versions.tf

#File =main.tf
locals {
#  region = var.region
}

# module "aws-vpc" {
#     source = "./modules/aws-vpc"
#     cidr = var.vpc_cidr
#     vpc_name = var.vpc_name
#     vpc_tags = var.vpc_tags
#     tags = var.tags
#     instance_tenancy = var.instance_tenancy
#     enable_dns_hostnames = var.enable_dns_hostnames
#     enable_dns_support = var.enable_dns_support
#     enable_ipv6 = var.enable_ipv6
#     create_vpc = var.create_vpc
# }

# module "aws-public-subnet" {
#     source = "./modules/aws-subnet"
#     count = length(var.public_subnets_cidr) > 0 ? 1 : 0
#     create_public_subnet = var.create_public_subnet
#     create_private_subnet = false
#     vpc_id = module.aws-vpc.vpc_id
#     public_subnets_names = var.public_subnets_names
#     public_subnets_cidr = var.public_subnets_cidr
#     public_subnets_azs = var.public_subnets_azs
#     map_public_ip_on_launch = var.map_public_ip_on_launch
#     public_subnet_assign_ipv6_address_on_creation = var.public_subnet_assign_ipv6_address_on_creation
#     public_subnets_tags = var.public_subnets_tags
#     assign_ipv6_address_on_creation = var.assign_ipv6_address_on_creation
#     tags = var.tags
#     depends_on = [
#     module.aws-vpc,
#   ]
# }

# module "aws-private-subnet" {
#     source = "./modules/aws-subnet"
#     count = length(var.private_subnets_cidr) > 0 ? 1 : 0
#     create_private_subnet = var.create_private_subnet
#     create_public_subnet = false
#     vpc_id = module.aws-vpc.vpc_id
# #    public_subnets_names = var.public_subnets_names
# #    public_subnets_cidr = var.public_subnets_cidr
# #    public_subnets_azs = var.public_subnets_azs
# #    map_public_ip_on_launch = var.map_public_ip_on_launch
# #    public_subnet_assign_ipv6_address_on_creation = var.public_subnet_assign_ipv6_address_on_creation
# #    public_subnets_tags = var.public_subnets_tags
#     assign_ipv6_address_on_creation = var.assign_ipv6_address_on_creation
#     tags = var.tags
#     private_subnets_names = var.private_subnets_names
#     private_subnets_cidr = var.private_subnets_cidr
#     private_subnets_azs = var.private_subnets_azs
#     private_subnet_assign_ipv6_address_on_creation = var.private_subnet_assign_ipv6_address_on_creation
#     private_subnets_tags = var.private_subnets_tags
#     depends_on = [
#     module.aws-vpc,
#   ]
# }

# module "aws-nacl" {
#   source = "./modules/aws-nacl"
#   vpc_id = module.aws-vpc.vpc_id
#   create_nacl = var.create_nacl
#   subnets_cidr = module.aws-public-subnet[0].public_subnets_id
#   nacl_names = var.nacl_names
#   inbound_acl_rules = var.inbound_acl_rules
#   outbound_acl_rules = var.outbound_acl_rules
#   tags = var.tags
#   depends_on = [
#     module.aws-public-subnet,
#   ]
# }

data "aws_vpc" "edocvpc" {
  id = "vpc-0e266d6eb76f273f5"
}
data "aws_subnet" "public_subnet" {
  id = "subnet-0c9de9484ebb2cc03"
}

# module "aws-ami" {
#   source = "./modules/aws-ami"
#   ami_name = var.ami_name
#   instance_id = var.instance_id_for_AMI
# }

module "aws-sg" {
  source = "./modules/aws-sg"
  vpc_id = data.aws_vpc.edocvpc.id
  security_group_name = var.security_group_name
  security_group_ingress = var.security_group_ingress
  security_group_egress = var.security_group_egress
  tags = var.tags
}

# module "aws-key" {
#   source = "./modules/aws-key"
# #  createprivkey = false
#   passpublickey = var.passpublickey                 
#   key_name = var.key_name
#   tags = var.tags
# }


# module "aws-ec2" {
#  source = "./modules/aws-ec2"
#   number_of_instances = var.number_of_instances
#   ec2_names = var.ec2_names
#   ec2_ami_ids = var.ec2_ami_ids
# #  ec2_ami_ids = [module.aws-ami.id]
#   instance_type = var.instance_type
#   ec2_key_names = ["Terra-cli"]
#   ec2_subnet_ids = ["subnet-0c9de9484ebb2cc03"]
#   ec2_security_group_ids = module.aws-sg.vpc_security_group_id[*]
#   monitoring = var.ec2_monitoring
#   get_password_data = var.get_password_data
#   associate_public_ip_address = var.associate_public_ip_address
#   tags = var.tags
#  }
# resource "null_resource" "localcontainer" {
#   # count = 3

#   # connection {
#   #   user = "ubuntu"
#   #   private_key="${file("/home/ubuntu/.ssh/id_rsa")}"
#   #   agent = true
#   #   timeout = "3m"
#   # }

#   provisioner "local-exec" {
#       command = <<-EOT
#       cat /etc/*-release
#       sudo apt-get install software-properties-common -y
#       sudo add-apt-repository ppa:deadsnakes/ppa
#       sudo apt-get update -y
#       sudo apt-get install python3.8 -y
#       python3 --version
#       python3 -m pip install --user ansible
#       ansible-playbook --version
#       EOT
# #     command = "ANSIBLE_HOST_KEY_CHECKING=False ansible-playbook -u ec2-user -i '${self.public_ip},' --private-key privatekey.pem -e apache-install.yml"
#    }
#      triggers = {
#      always_run = timestamp()
#   }
# }

# resource "null_resource" "remotevm" {
   
#    provisioner "remote-exec" {
#       inline = ["echo Done!"]

#       connection {
#         host        = "${element(module.aws-ec2.instance_public_ip, 0)}"
#         type        = "ssh"
#         user        = "ec2-user"
#         private_key = file("privatekey.pem")
#       }
#     }
#   provisioner "remote-exec" {
#       inline = [
#       "cd ansible",
#       "pwd",
#       "ANSIBLE_HOST_KEY_CHECKING=False  ansible-playbook --ssh-common-args='-o StrictHostKeyChecking=no' -u ec2-user -i '${element(module.aws-ec2.instance_public_ip, 0)},' --private-key privatekey.pem ping.yml"
#     ]
#     connection {
#      host        = "10.210.0.231"
#      type        = "ssh"
#      user = "admin_terraform@clopsapp.com"
#      password = var.remotevmpassword
#      #private_key="${file("/home/ubuntu/.ssh/id_rsa")}"
#    }
# #     command = "ANSIBLE_HOST_KEY_CHECKING=False ansible-playbook -u ec2-user -i '${self.public_ip},' --private-key privatekey.pem -e apache-install.yml"
#    }
#      triggers = {
#      always_run = timestamp()
#   }
# }

# variable "remotevmpassword" {
#   type = string
# }

#File =output.tf
# output "private_key_pair" {
#     value = "${module.aws-key.private_key}"
#     sensitive = true
# }

# output "instance_public_ip" {
#   description = "Public IP address of the EC2 instance"
#   value       = "${module.aws-ec2.instance_public_ip}"
# }
#File =provider.tf
# Configure the AWS Provider
provider "aws" {
  region     = "ap-south-1"
  access_key = var.AWS_ACCESS_KEY_ID
  secret_key = var.AWS_SECRET_ACCESS_KEY
}

#File =variables.tf
variable "AWS_ACCESS_KEY_ID" {
  type = string
}

variable "AWS_SECRET_ACCESS_KEY" {
  type = string
}

# variable "create_vpc" {
#     type = bool
#     default = true
# }

# variable "vpc_name" {
#   description = "VPC Name"
#   type        = string
#   default     = ""
# }

# variable "vpc_cidr" {
#   description = "The CIDR block for the VPC."
#   type        = string
# }

# variable "instance_tenancy" {
#   description = "A tenancy option for instances launched into the VPC"
#   type        = string
#   default     = "default"
# }

# variable "enable_dns_hostnames" {
#   description = "Should be true to enable DNS hostnames in the VPC"
#   type        = bool
#   default     = true
# }

# variable "enable_dns_support" {
#   description = "Should be true to enable DNS support in the VPC"
#   type        = bool
#   default     = true
# }

# variable "enable_ipv6" {
#   description = "Requests an Amazon-provided IPv6 CIDR block with a /56 prefix length for the VPC. You cannot specify the range of IP addresses, or the size of the CIDR block."
#   type        = bool
#   default     = false
# }
# variable "vpc_tags" {
#   description = "A map of tags to add to all resources"
#   type        = map(string)
#   default     = {}
# }

variable "tags" {
  description = "A map of tags to add to all resources"
  type        = map(string)
  default     = { "Environment" = "Dev"
     "IaC" = "Terraform"
     "Team" = "Rapidops"} 
}


# variable "create_public_subnet" {
#     type = bool
#     default = true
# }
# variable "public_subnets_cidr" {
#     type = list(string)
#     default = []
# }
# variable "public_subnets_azs" {
#     type = list(string)
# }
# variable "map_public_ip_on_launch" {
#     type = bool
#     default = false
# }
# variable "public_subnet_assign_ipv6_address_on_creation" {
#     type = bool
#     default = null
# }
# variable "assign_ipv6_address_on_creation" {
#     type = bool
#     default = false
# }
# variable "public_subnets_names" {
#     type = list(string)
# }
# variable "public_subnets_tags" {
#     type = map(string)
# }
# variable "create_private_subnet" {
#     type = bool
#     default = true
# }
# variable "private_subnets_cidr" {
#     type = list(string)
# }
# variable "private_subnets_azs" {
#     type = list(string)
# }
# variable "private_subnet_assign_ipv6_address_on_creation" {
#     type = bool
#     default = null
# }
# variable "private_subnets_names" {
#     type = list(string)
# }
# variable "private_subnets_tags" {
#     type = map(string)
# }



# #Variables for NACL. Tags and vpc id is different from modules

# variable "create_nacl" {
#  type = bool
#  default = false
# }
# variable "nacl_names" {
#  type = list(string)
#  default = []
# }
# variable "inbound_acl_rules" { 
#   type = list(map(string))
# #  default = [
# #    {
# #      rule_number = 100
# #      rule_action = "allow"
# #      from_port   = 0
# #      to_port     = 0
# #      protocol    = "-1"
# #      cidr_block  = "0.0.0.0/0"
# #    },
# #  ]

# }
# variable "outbound_acl_rules" {
#     type = list(map(string))
# #    default = [
# #    {
# #      rule_number = 100
# #      rule_action = "allow"
# #      from_port   = 0
# #      to_port     = 0
# #      protocol    = "-1"
# #      cidr_block  = "0.0.0.0/0"
# #    },
# #  ]
  
# }


# AMI

# variable "ami_name" {
#   type = string
#   default = "AMI-Through-Terraform"
# }
# variable "instance_id_for_AMI" {
#   type = string
#   default = "i-0f6c78b40f01e4bec" 
# }

# Security Group
variable "security_group_name" {
  description = "Name to be used on the custom security group"
  type        = string
  #default = "Terra_Rapidops_SG"
}
variable "security_group_ingress" {
  description = "List of maps of ingress rules to set on the custom security group"
  type        = list(object({
    description = string
    from_port   = number
    to_port     = number
    protocol    = string
    cidr_blocks = list(string)
  }))
  default     = [{
         description = "SSH"
         from_port = 22
         to_port   = 22
         protocol  = "tcp"
         cidr_blocks = ["0.0.0.0/0"]
        }, {
         description = "HTTP"
         from_port = 8080
         to_port   = 8080
         protocol  = "tcp"
         cidr_blocks = ["0.0.0.0/0"]
     },
      {
         description = "HTTPS"
         from_port = 443
         to_port   = 443
         protocol  = "tcp"
         cidr_blocks = ["0.0.0.0/0"]
     },
      {
         description = "HTTPS"
         from_port = 8089
         to_port   = 8089
         protocol  = "tcp"
         cidr_blocks = ["0.0.0.0/0"]
     }]
}
variable "security_group_egress" {
  description = "List of maps of egress rules to set on the custom security group"
  type        = list(object({
    description = string
    from_port   = number
    to_port     = number
    protocol    = string
    cidr_blocks = list(string)
  }))
  default     = [{
         description = ""
         from_port = 0
         to_port   = 0
         protocol  = "tcp"
         cidr_blocks = ["0.0.0.0/0"]
        }]
}


 #Key

# variable "createprivkey" {
#     type = bool
#     default = false
# }
# variable "key_name" {
#     type = string
#     default = "Terraform-dev-Key"
# }

#  variable "passpublickey" {
#      type = bool
#      default = true 
#  }

# variable "public_key" {
#     type = string
#     default = ""
# }



# #EC2 Instances

# variable "number_of_instances" {
#   type = number
#   default = 1
# }
# variable "ec2_names" {
#   type = list(string)
#   default = ["Terra-Dev-Splunk-App", "Terra-Dev-Splunk-DB"]
# }
# variable "ec2_ami_ids" {
#   type = list(string)
#   default = ["ami-068257025f72f470d"]
# }
# variable "instance_type" {
#   type = list(string)
#   default =  [""]
# }
# variable "ec2_key_names" {
#   type = list(string)
#   default = []
# }
# variable "ec2_subnet_id" {
#   type = list(string)
#   default = []
# }
# variable "ec2_security_group_ids" {
#   type = list(string)
#   default = []
# }
# variable "ec2_monitoring" {
#   type = bool
#   default = false
# }
# variable "get_password_data" {
#   type = bool 
#   default = false
# }
# variable "associate_public_ip_address" {
#   type = bool
#   default = true
# }
# variable "ec2_private_ips" {
#   type = list(string) 
#   default = []
# }
# variable "ec2_secondary_private_ips" {
#    type = list(string)
#    default = []
# }
# variable "ec2_ipv6_addresses" {
#    type = list(string)
#    default = []
# }
# variable "ebs_optimized" {
#    type = bool
#    default = false
# }

# #Internet Gateway
# variable "create_igw" {
#   type = bool
#   default = false
# }

# #Route Table
# variable "create_rt" {
#   type = bool
#   default = false
# }

# variable "route_table_routes" {
#     type = list(map(string))
#     default = []
# }

# variable "rt_name" {
#     type = string  
# }

# variable "rt_cidr_block" {
#     type = string  
# }

#File =versions.tf
#Mention Terraform and Providers version
terraform {
  required_version = ">= 1.0"

 #backend "s3" {
 #   bucket = "terraform-usecases"
 #   key    = "statefiles/terraform.tfstate"
 #   region = "ap-south-1"
 # }

#backend "s3" {
#   
#  }

#  cloud {
#    organization = "Rapid"

#    workspaces {
#      name = "environment-replications-dev"
#    }
#  }
# backend "remote" {
#   hostname = "10.210.0.33"
#   organization = "EDOC"
#   workspaces {
#     name = "environment-replication-ansible"
#   }
# }

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 3.63"
    }
  }
  
}

