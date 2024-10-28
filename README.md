# EKS Fargate Deployment with Docker Host and ECR Integration

## Introduction

This Terraform project sets up an AWS EKS Fargate cluster configured to deploy a web application using ECR as the container image registry. Additionally, the configuration provisions an EC2 instance with Docker installed, serving as a Docker host to build and push custom images to ECR. 

This setup includes an AWS Load Balancer Controller to automatically create an Application Load Balancer (ALB) for your services. This is ideal for deploying web applications on Fargate-managed nodes, especially when needing to build custom images directly in AWS.

## Features

- **EKS Fargate Cluster**: Fully managed Kubernetes cluster using Fargate to simplify scaling and maintenance.
- **Docker Host**: An EC2 instance with Docker installed, providing an environment for building and pushing custom images.
- **ECR Integration**: Allows easy pushing of Docker images to an ECR repository accessible by EKS.
- **AWS Load Balancer Controller**: Automatically provisions an Application Load Balancer (ALB) for service access.

## Terraform Resources

The following resources are provisioned:

- **EKS Cluster**: A managed Kubernetes control plane with Fargate profiles for serverless pod deployment.
- **ECR Repository**: Stores Docker images for deployment on the EKS cluster.
- **IAM Roles and Policies**: Access roles for ECR, EKS, and ALB, including the necessary permissions for ECR and load balancer controller.
- **Docker Host (EC2 instance)**: An Ubuntu instance with Docker and AWS CLI installed, for building and pushing images to ECR.
- **Application Load Balancer (ALB)**: Created via AWS Load Balancer Controller to expose services on EKS.

## Prerequisites

Before you begin, ensure the following are installed on your local machine:

- [Terraform](https://www.terraform.io/downloads.html) v1.0+
- [AWS CLI](https://aws.amazon.com/cli/)
- [kubectl](https://kubernetes.io/docs/tasks/tools/)
- An AWS account and IAM user with the required permissions for EKS, EC2, ECR, and ALB resources.

## Usage

1. Clone the Repository. 

```
git clone https://github.com/your-username/eks-fargate-ecr-docker-host.git
cd eks-fargate-ecr-docker-host
```

2. Initialize Terraform
```
terraform init
```

3. Apply Terraform Configuration
```
terraform apply
```
Type ```yes``` to confirm.

Note: It will take awhile for the full deployment. Please run through the following steps to initialize the EKS cluster. Unfortunately, I can't figure a way to fully automate this yet.

4. Once deployed completed, run the following to initialize ```kubectl``` configuration to access the EKS cluster.
```
aws eks update-kubeconfig --region <region name> --name <cluster name>
```
Note: The default region is ```ap-southeast-1```, and the default cluster name is ```dvwa-eks-cluster```.

4. Check on the pods deployed in ```kube-system``` namespace and reload ```coredns```:
```
kubectl get pods -n kube-system
```
You should see something like the following:
```
NAME                                            READY   STATUS    RESTARTS   AGE
aws-load-balancer-controller-589bffd4cf-8mnpl   1/1     Running   0          12m
aws-load-balancer-controller-589bffd4cf-ngqxh   1/1     Running   0          12m
coredns-5bdf9966f5-dc5fv                        0/1     Pending   0          4h25m
coredns-5bdf9966f5-w4tdd                        0/1     Pending   0          4h25m
```
This shows that the ```coredns``` pods are not deployed yet, which means DNS would not be functioning in your cluster. To restart/reload ```coredns``` deployment, run the following:

```
kubectl rollout restart -n kube-system deployment/coredns 
```

5. Check on the ALB FQDN with the following:
```
kubectl get ingress -n dvwa
```
Note: You will need to wait for a couple of minutes till you see the FQDN showed under ```ADDRESS```. Also, it will also take a couple more minutes till you will be able to access DVWA web application, as it takes time for ALB to be provisioned.

