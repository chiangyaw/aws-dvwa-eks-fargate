# providers.tf
provider "aws" {
  region = var.region # Update region as per your requirement
}

variable "region" {
    default = "ap-southeast-1"
}

variable "image_uri"{
    default = "vulnerables/web-dvwa"
    #default = "${aws_ecr_repository.dvwa_repo.repository_url}:latest"  # Replace with ECR repo URI if needed
}

provider "kubernetes" {
  host                   = aws_eks_cluster.eks_cluster.endpoint
  cluster_ca_certificate = base64decode(aws_eks_cluster.eks_cluster.certificate_authority[0].data)
  token                  = data.aws_eks_cluster_auth.eks.token
}

provider "helm" {
  kubernetes {
    host                   = aws_eks_cluster.eks_cluster.endpoint
    token                  = data.aws_eks_cluster_auth.eks.token
    cluster_ca_certificate = base64decode(aws_eks_cluster.eks_cluster.certificate_authority[0].data)
  }
}

data "aws_eks_cluster_auth" "eks" {
  name = aws_eks_cluster.eks_cluster.name
}

# eks-cluster.tf
resource "aws_eks_cluster" "eks_cluster" {
  name     = "dvwa-eks-cluster"
  role_arn = aws_iam_role.eks_cluster_role.arn

  vpc_config {
    subnet_ids = aws_subnet.eks_subnet[*].id
  }

  depends_on = [aws_iam_role_policy_attachment.eks_cluster_AmazonEKSClusterPolicy]
}

# Fargate profile
resource "aws_eks_fargate_profile" "fargate_profile" {
  cluster_name           = aws_eks_cluster.eks_cluster.name
  fargate_profile_name   = "dvwa-fargate-profile"
  pod_execution_role_arn = aws_iam_role.eks_fargate_pod_execution_role.arn
  subnet_ids             = aws_subnet.eks_private_subnet[*].id

  selector {
    namespace = "dvwa"
  }

  depends_on = [aws_eks_cluster.eks_cluster]
}

resource "aws_eks_fargate_profile" "kube_system_fargate_profile" {
  cluster_name           = aws_eks_cluster.eks_cluster.name
  fargate_profile_name   = "kube-system-fargate-profile"
  pod_execution_role_arn = aws_iam_role.eks_fargate_pod_execution_role.arn
  subnet_ids             = aws_subnet.eks_private_subnet[*].id

  selector {
    namespace = "kube-system"
  }

  depends_on = [aws_eks_cluster.eks_cluster]
}

# IAM roles and policies
resource "aws_iam_role" "eks_cluster_role" {
  name = "eks-cluster-role-2"

  assume_role_policy = jsonencode({
    Statement = [{
      Action    = "sts:AssumeRole",
      Effect    = "Allow",
      Principal = {
        Service = "eks.amazonaws.com"
      }
    }],
    Version = "2012-10-17"
  })
}

resource "aws_iam_role_policy_attachment" "eks_cluster_AmazonEKSClusterPolicy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
  role       = aws_iam_role.eks_cluster_role.name
}

resource "aws_iam_role" "eks_fargate_pod_execution_role" {
  name = "eks-fargate-pod-execution-role"

  assume_role_policy = jsonencode({
    Statement = [{
      Action    = "sts:AssumeRole",
      Effect    = "Allow",
      Principal = {
        Service = "eks-fargate-pods.amazonaws.com"
      }
    }],
    Version = "2012-10-17"
  })
}

resource "aws_iam_role_policy_attachment" "fargate_AmazonEKSFargatePodExecutionRolePolicy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSFargatePodExecutionRolePolicy"
  role       = aws_iam_role.eks_fargate_pod_execution_role.name
}

# VPC Configuration (Subnet, Internet Gateway, etc.)
resource "aws_vpc" "eks_vpc" {
  cidr_block = "10.0.0.0/16"
}

resource "aws_subnet" "eks_subnet" {
  count             = 2
  vpc_id            = aws_vpc.eks_vpc.id
  cidr_block        = cidrsubnet(aws_vpc.eks_vpc.cidr_block, 8, count.index)
  availability_zone = element(data.aws_availability_zones.available.names, count.index + 2)

  tags = {
    Name = "eks_subnet_${count.index + 1}"
    "kubernetes.io/role/elb" = "1"
  }
}

resource "aws_subnet" "eks_private_subnet" {
  count             = 2
  vpc_id            = aws_vpc.eks_vpc.id
  cidr_block        = cidrsubnet(aws_vpc.eks_vpc.cidr_block, 8, count.index + 2)
  availability_zone = element(data.aws_availability_zones.available.names, count.index + 2)
  tags = {
    Name = "eks_private_subnet_${count.index + 1}"
    "kubernetes.io/role/internal-elb" = "1"
  }
}

data "aws_availability_zones" "available" {}

resource "aws_internet_gateway" "eks_igw" {
  vpc_id = aws_vpc.eks_vpc.id
}

resource "aws_route_table" "eks_route_table" {
  vpc_id = aws_vpc.eks_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.eks_igw.id
  }
}

resource "aws_route_table_association" "eks_rta" {
  count          = 2
  subnet_id      = element(aws_subnet.eks_subnet[*].id, count.index)
  route_table_id = aws_route_table.eks_route_table.id
}

resource "aws_eip" "nat_eip" {
  domain = "vpc"
}

resource "aws_nat_gateway" "nat_gateway" {
  allocation_id = aws_eip.nat_eip.id
  subnet_id     = aws_subnet.eks_subnet[0].id
}

# Private Route Table for Private Subnets
resource "aws_route_table" "private_route_table" {
  vpc_id = aws_vpc.eks_vpc.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.nat_gateway.id
  }
}


resource "aws_route_table_association" "private_rta" {
  count          = 2
  subnet_id      = element(aws_subnet.eks_private_subnet[*].id, count.index)
  route_table_id = aws_route_table.private_route_table.id
}



# Kubernetes resources (Namespace and Deployment)
resource "kubernetes_namespace" "dvwa" {
  metadata {
    name = "dvwa"
  }
}

resource "kubernetes_deployment" "dvwa_deployment" {
  metadata {
    name      = "dvwa"
    namespace = kubernetes_namespace.dvwa.metadata[0].name
  }

  spec {
    replicas = 1

    selector {
      match_labels = {
        app = "dvwa"
      }
    }

    template {
      metadata {
        labels = {
          app = "dvwa"
        }
      }

      spec {
        service_account_name = kubernetes_service_account.dvwa_sa.metadata[0].name  # Using the dvwa-sa service account
        container {
          name  = "dvwa-container"
          image = var.image_uri

          port {
            container_port = 80
          }
        }
      }
    }
  }
}

# Kubernetes Service for DVWA
resource "kubernetes_service" "dvwa_service" {
  metadata {
    name      = "dvwa-service"
    namespace = kubernetes_namespace.dvwa.metadata[0].name
  }

  spec {
    selector = {
      app = "dvwa"
    }

    port {
      port        = 80
      target_port = 80
    }

    type = "LoadBalancer"
  }

  # Wait until the LoadBalancer is assigned an IP or DNS
  lifecycle {
    ignore_changes = [
      spec[0].load_balancer_ip, 
      status[0].load_balancer[0].ingress[0].ip,
      status[0].load_balancer[0].ingress[0].hostname
    ]
  }
}


# Create IAM Policy for AWS Load Balancer Controller
resource "aws_iam_policy" "load_balancer_controller_policy" {
  name        = "AWSLoadBalancerControllerIAMPolicy"
  description = "IAM policy for AWS Load Balancer Controller"

  policy      = jsonencode({
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Action": [
          "acm:DescribeCertificate",
          "acm:ListCertificates",
          "acm:GetCertificate"
        ],
        "Resource": "*"
      },
      {
        "Effect": "Allow",
        "Action": [
          "ec2:AuthorizeSecurityGroupIngress",
          "ec2:RevokeSecurityGroupIngress"
        ],
        "Resource": "*"
      },
      {
        "Effect": "Allow",
        "Action": [
          "ec2:CreateSecurityGroup"
        ],
        "Resource": "*"
      },
      {
        "Effect": "Allow",
        "Action": [
          "ec2:CreateTags"
        ],
        "Resource": "arn:aws:ec2:*:*:security-group/*",
        "Condition": {
          "StringEquals": {
            "ec2:CreateAction": "CreateSecurityGroup"
          }
        }
      },
      {
        "Effect": "Allow",
        "Action": [
          "ec2:DeleteSecurityGroup"
        ],
        "Resource": "*"
      },
      {
        "Effect": "Allow",
        "Action": [
          "ec2:DescribeAccountAttributes",
          "ec2:DescribeAddresses",
          "ec2:DescribeAvailabilityZones",
          "ec2:DescribeInternetGateways",
          "ec2:DescribeVpcs",
          "ec2:DescribeSubnets",
          "ec2:DescribeSecurityGroups",
          "ec2:DescribeInstances",
          "ec2:DescribeNetworkInterfaces",
          "ec2:DescribeTags",
          "ec2:GetCoipPoolUsage",
          "ec2:DescribeCoipPools"
        ],
        "Resource": "*"
      },
      {
        "Effect": "Allow",
        "Action": [
          "ec2:CreateNetworkInterface",
          "ec2:DeleteNetworkInterface",
          "ec2:DescribeNetworkInterfacePermissions",
          "ec2:ModifyNetworkInterfaceAttribute",
          "ec2:AssignPrivateIpAddresses",
          "ec2:UnassignPrivateIpAddresses"
        ],
        "Resource": "*"
      },
      {
        "Effect": "Allow",
        "Action": [
          "elasticloadbalancing:AddListenerCertificates",
          "elasticloadbalancing:AddTags",
          "elasticloadbalancing:CreateListener",
          "elasticloadbalancing:CreateLoadBalancer",
          "elasticloadbalancing:CreateRule",
          "elasticloadbalancing:CreateTargetGroup",
          "elasticloadbalancing:DeleteListener",
          "elasticloadbalancing:DeleteLoadBalancer",
          "elasticloadbalancing:DeleteRule",
          "elasticloadbalancing:DeleteTargetGroup",
          "elasticloadbalancing:DeregisterTargets",
          "elasticloadbalancing:DescribeListenerCertificates",
          "elasticloadbalancing:DescribeListeners",
          "elasticloadbalancing:DescribeLoadBalancers",
          "elasticloadbalancing:DescribeLoadBalancerAttributes",
          "elasticloadbalancing:DescribeRules",
          "elasticloadbalancing:DescribeSSLPolicies",
          "elasticloadbalancing:DescribeTags",
          "elasticloadbalancing:DescribeTargetGroups",
          "elasticloadbalancing:DescribeTargetGroupAttributes",
          "elasticloadbalancing:DescribeTargetHealth",
          "elasticloadbalancing:ModifyListener",
          "elasticloadbalancing:ModifyLoadBalancerAttributes",
          "elasticloadbalancing:ModifyRule",
          "elasticloadbalancing:ModifyTargetGroup",
          "elasticloadbalancing:ModifyTargetGroupAttributes",
          "elasticloadbalancing:RegisterTargets",
          "elasticloadbalancing:RemoveListenerCertificates",
          "elasticloadbalancing:RemoveTags",
          "elasticloadbalancing:SetIpAddressType",
          "elasticloadbalancing:SetSecurityGroups",
          "elasticloadbalancing:SetSubnets",
          "elasticloadbalancing:SetWebAcl"
        ],
        "Resource": "*"
      },
      {
        "Effect": "Allow",
        "Action": [
          "iam:CreateServiceLinkedRole",
          "iam:GetServerCertificate",
          "iam:ListServerCertificates"
        ],
        "Resource": "*"
      },
      {
        "Effect": "Allow",
        "Action": [
          "cognito-idp:DescribeUserPoolClient"
        ],
        "Resource": "*"
      },
      {
        "Effect": "Allow",
        "Action": [
          "waf-regional:GetWebACLForResource",
          "waf-regional:GetWebACL",
          "waf-regional:AssociateWebACL",
          "waf-regional:DisassociateWebACL"
        ],
        "Resource": "*"
      },
      {
        "Effect": "Allow",
        "Action": [
          "tag:GetResources",
          "tag:TagResources"
        ],
        "Resource": "*"
      },
      {
        "Effect": "Allow",
        "Action": [
          "wafv2:GetWebACLForResource",
          "wafv2:GetWebACL",
          "wafv2:AssociateWebACL",
          "wafv2:DisassociateWebACL"
        ],
        "Resource": "*"
      },
      {
        "Effect": "Allow",
        "Action": [
          "shield:DescribeProtection",
          "shield:GetSubscriptionState",
          "shield:DeleteProtection",
          "shield:CreateProtection",
          "shield:DescribeSubscription",
          "shield:ListProtections"
        ],
        "Resource": "*"
      }
    ]
  })
}

resource "aws_iam_openid_connect_provider" "eks_oidc_provider" {
  client_id_list  = ["sts.amazonaws.com"]
  url             = aws_eks_cluster.eks_cluster.identity[0].oidc[0].issuer
  thumbprint_list = ["9e99a48a9960e645e9bbb8d91f37e3bb9d34a0c3"]
}

# Create IAM Role for Load Balancer Controller
resource "aws_iam_role" "lb_controller_role" {
  name = "aws-load-balancer-controller"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Principal = {
          Federated = aws_iam_openid_connect_provider.eks_oidc_provider.arn
        },
        Action = "sts:AssumeRoleWithWebIdentity",
        Condition = {
        StringEquals = {
          "${replace(aws_eks_cluster.eks_cluster.identity[0].oidc[0].issuer, "https://", "")}:sub" = "system:serviceaccount:kube-system:aws-load-balancer-controller"
            }
        }
      }
    ]
  })
}

# Attach the IAM Policy to the Load Balancer Controller Role
resource "aws_iam_role_policy_attachment" "lb_controller_policy_attach" {
  policy_arn = aws_iam_policy.load_balancer_controller_policy.arn
  role       = aws_iam_role.lb_controller_role.name
}

resource "kubernetes_service_account" "lb_controller_sa" {
  metadata {
    name      = "aws-load-balancer-controller"
    namespace = "kube-system"
    annotations = {
      "eks.amazonaws.com/role-arn" = aws_iam_role.lb_controller_role.arn
    }
  }
}





# Deploy the AWS Load Balancer Controller using Helm
resource "helm_release" "load_balancer_controller" {
  name       = "aws-load-balancer-controller"
  repository = "https://aws.github.io/eks-charts"
  chart      = "aws-load-balancer-controller"
  namespace  = "kube-system"
  version    = "1.9.2" # Update with the latest version

  set {
    name  = "clusterName"
    value = aws_eks_cluster.eks_cluster.name
  }

  set {
    name  = "serviceAccount.create"
    value = "false"
  }

  set {
    name  = "serviceAccount.name"
    value = aws_iam_role.lb_controller_role.name
  }

  set {
    name = "vpcId"
    value = aws_vpc.eks_vpc.id
  }
  set {
    name = "region"
    value = var.region
  }
}

# Create Ingress Resource
resource "kubernetes_ingress_v1" "dvwa_ingress" {
  metadata {
    name      = "dvwa-ingress"
    namespace = "dvwa"
    annotations = {
      "kubernetes.io/ingress.class"             = "alb"
      "alb.ingress.kubernetes.io/scheme"         = "internet-facing"
      "alb.ingress.kubernetes.io/target-type"    = "ip"
      "alb.ingress.kubernetes.io/listen-ports"    = "[{\"HTTP\": 80}]"
      "alb.ingress.kubernetes.io/backend-protocol" = "HTTP"
    }
  }

  spec {
    rule {
      http {
        path {
          path     = "/"
          path_type = "Prefix"
          backend {
            service {
              name = kubernetes_service.dvwa_service.metadata[0].name
              port {
                number = 80
              }
            }
          }
        }
      }
    }
  }
}


# Create ECR repository
resource "aws_ecr_repository" "dvwa_repo" {
  name = "dvwa-app-repo"

  image_scanning_configuration {
    scan_on_push = false
  }

  tags = {
    Name = "dvwa-app-repo"
  }
}

# Creating IAM Policy for ECR Access

resource "aws_iam_policy" "fargate_ecr_policy" {
  name        = "Fargate-ECR-AccessPolicy"
  description = "IAM policy for EKS Fargate ECR Access"

  policy      = jsonencode({
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Action": [
          "ecr:GetDownloadUrlForLayer",
      "ecr:BatchGetImage",
      "ecr:BatchCheckLayerAvailability"
        ],
        "Resource": "*"
      }
    ]
  })
}

resource "aws_iam_role" "fargate_ecr_role" {
  name = "eks-fargate-ecr-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Federated = aws_iam_openid_connect_provider.eks_oidc_provider.arn
      }
      Action = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = {
          "${replace(aws_eks_cluster.eks_cluster.identity[0].oidc[0].issuer, "https://", "")}:sub" = "system:serviceaccount:dvwa:dvwa-sa"
        }
      }
    }]
  })
}

# Attach the ECR access policy to the IAM role
resource "aws_iam_role_policy_attachment" "fargate_ecr_access" {
  role       = aws_iam_role.fargate_ecr_role.name
  policy_arn = aws_iam_policy.fargate_ecr_policy.arn
}

# Create a Kubernetes Service Account and link it to the IAM role
resource "kubernetes_service_account" "dvwa_sa" {
  metadata {
    name      = "dvwa-sa"
    namespace = "dvwa"
    annotations = {
      "eks.amazonaws.com/role-arn" = aws_iam_role.fargate_ecr_role.arn
    }
  }
}

# Instance to build docker image and push to ECR
# Generate an SSH key locally
resource "tls_private_key" "docker_host_key" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

# Save the private key locally as a PEM file
resource "local_file" "private_key_pem" {
  content  = tls_private_key.docker_host_key.private_key_pem
  filename = "${path.module}/docker-host-key.pem"  # PEM file path, change as needed
}

# Create an AWS Key Pair with the generated public key
resource "aws_key_pair" "docker_host_key_pair" {
  key_name   = "docker_host_key_pair.pem"
  public_key = tls_private_key.docker_host_key.public_key_openssh
}

# Security group to allow SSH access
resource "aws_security_group" "docker_host_sg" {
  name        = "docker-host-sg"
  description = "Allow SSH access to Docker host"
  vpc_id      = aws_vpc.eks_vpc.id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # Replace with your IP for better security
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# IAM policy for ECR access
resource "aws_iam_policy" "ecr_push_policy" {
  name = "ECRPushPolicy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ecr:GetDownloadUrlForLayer",
          "ecr:BatchGetImage",
          "ecr:BatchCheckLayerAvailability",
          "ecr:PutImage",
          "ecr:InitiateLayerUpload",
          "ecr:UploadLayerPart",
          "ecr:CompleteLayerUpload",
          "ecr:GetAuthorizationToken"
        ]
        Resource = "*"
      }
    ]
  })
}

# IAM role for EC2 instance with ECR access
resource "aws_iam_role" "docker_host_role" {
  name = "DockerHostECRRole"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

# Attach the ECR policy to the IAM role
resource "aws_iam_role_policy_attachment" "docker_host_ecr_access" {
  role       = aws_iam_role.docker_host_role.name
  policy_arn = aws_iam_policy.ecr_push_policy.arn
}

# IAM instance profile for EC2 instance
resource "aws_iam_instance_profile" "docker_host_profile" {
  name = "DockerHostInstanceProfile"
  role = aws_iam_role.docker_host_role.name
}

data "aws_ami" "aws_ubuntu" {
  most_recent = true
  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }
  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
  owners = ["679593333241"]
}

resource "aws_instance" "docker_host" {
  ami                    = data.aws_ami.aws_ubuntu.id
  instance_type          = "t2.medium"
  vpc_security_group_ids = [aws_security_group.docker_host_sg.id]
  subnet_id              = aws_subnet.eks_subnet[0].id

  iam_instance_profile = aws_iam_instance_profile.docker_host_profile.name

  tags = {
    Name = "docker-host"
  }

  user_data = <<-EOF
    #!/bin/bash
    sudo apt-get update -y
    sudo apt-get install -y docker.io
    sudo systemctl start docker
    sudo systemctl enable docker

    # Install AWS CLI for pushing to ECR
    sudo apt-get install -y awscli

    # Add ubuntu user to the docker group
    sudo usermod -aG docker ubuntu
  EOF

  associate_public_ip_address = true  # Ensures the instance is accessible publicly
  key_name                    = aws_key_pair.docker_host_key_pair.key_name  # Replace with your SSH key name
}

# Output the public IP address for easy access
output "docker_host_public_ip" {
  value       = aws_instance.docker_host.public_ip
  description = "Public IP address of the Docker host instance"
}



# (NO LONGER REQUIRED) Terraform Output to get Public IP or DNS of the LoadBalancer
# output "dvwa_application_endpoint" {
#   description = "The DNS or Public IP address of the DVWA web application."

#   value = kubernetes_service.dvwa_service.status[0].load_balancer[0].ingress[0].hostname != "" ? kubernetes_service.dvwa_service.status[0].load_balancer[0].ingress[0].hostname : kubernetes_service.dvwa_service.status[0].load_balancer[0].ingress[0].ip
# }


# Output the ALB FQDN
# output "alb_fqdn" {
#   value = kubernetes_ingress_v1.dvwa_ingress.status[0].load_balancer[0].ingress[0].hostname
#   description = "The DNS name of the ALB for the DVWA application."
# }
