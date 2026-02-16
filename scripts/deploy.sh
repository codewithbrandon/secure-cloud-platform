#!/bin/bash

# =============================================================================
# SECURE CLOUD PLATFORM - DEPLOYMENT SCRIPT
# =============================================================================
# This script automates the deployment of the entire platform
#
# Usage:
#   ./scripts/deploy.sh [command]
#
# Commands:
#   init      - Initialize Terraform
#   plan      - Run Terraform plan
#   apply     - Apply Terraform configuration
#   destroy   - Destroy all resources
#   app       - Deploy application to AKS
#   all       - Full deployment (infrastructure + application)
# =============================================================================

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
TERRAFORM_DIR="$PROJECT_ROOT/terraform"
K8S_DIR="$PROJECT_ROOT/k8s"
APP_DIR="$PROJECT_ROOT/app"

# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_prerequisites() {
    log_info "Checking prerequisites..."

    # Check Azure CLI
    if ! command -v az &> /dev/null; then
        log_error "Azure CLI is not installed"
        exit 1
    fi

    # Check Terraform
    if ! command -v terraform &> /dev/null; then
        log_error "Terraform is not installed"
        exit 1
    fi

    # Check kubectl
    if ! command -v kubectl &> /dev/null; then
        log_error "kubectl is not installed"
        exit 1
    fi

    # Check Docker
    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed"
        exit 1
    fi

    # Check Azure login
    if ! az account show &> /dev/null; then
        log_warning "Not logged in to Azure. Running 'az login'..."
        az login
    fi

    log_success "All prerequisites met"
}

# =============================================================================
# TERRAFORM FUNCTIONS
# =============================================================================

terraform_init() {
    log_info "Initializing Terraform..."
    cd "$TERRAFORM_DIR"
    terraform init
    log_success "Terraform initialized"
}

terraform_plan() {
    log_info "Running Terraform plan..."
    cd "$TERRAFORM_DIR"

    if [ ! -f "terraform.tfvars" ]; then
        log_error "terraform.tfvars not found. Copy from terraform.tfvars.example and configure."
        exit 1
    fi

    terraform plan -out=tfplan
    log_success "Terraform plan complete. Review the plan above."
}

terraform_apply() {
    log_info "Applying Terraform configuration..."
    cd "$TERRAFORM_DIR"

    if [ ! -f "tfplan" ]; then
        log_warning "No plan file found. Running plan first..."
        terraform_plan
    fi

    echo ""
    read -p "Do you want to apply this plan? (yes/no): " confirm
    if [ "$confirm" != "yes" ]; then
        log_warning "Deployment cancelled"
        exit 0
    fi

    terraform apply tfplan
    log_success "Infrastructure deployed successfully"

    # Save outputs
    terraform output -json > outputs.json
    log_info "Outputs saved to outputs.json"
}

terraform_destroy() {
    log_warning "This will DESTROY all infrastructure!"
    echo ""
    read -p "Are you absolutely sure? Type 'destroy' to confirm: " confirm
    if [ "$confirm" != "destroy" ]; then
        log_info "Destroy cancelled"
        exit 0
    fi

    cd "$TERRAFORM_DIR"
    terraform destroy
    log_success "Infrastructure destroyed"
}

# =============================================================================
# APPLICATION DEPLOYMENT
# =============================================================================

deploy_app() {
    log_info "Deploying application to AKS..."

    # Get AKS credentials
    RESOURCE_GROUP=$(terraform -chdir="$TERRAFORM_DIR" output -raw resource_group_name 2>/dev/null || echo "rg-seccloud-prod")
    AKS_NAME=$(terraform -chdir="$TERRAFORM_DIR" output -raw aks_cluster_name 2>/dev/null || echo "aks-seccloud-prod")
    ACR_NAME=$(terraform -chdir="$TERRAFORM_DIR" output -raw acr_name 2>/dev/null || echo "acrseccloudprod")

    log_info "Getting AKS credentials..."
    az aks get-credentials --resource-group "$RESOURCE_GROUP" --name "$AKS_NAME" --overwrite-existing

    log_info "Logging in to ACR..."
    az acr login --name "$ACR_NAME"

    # Build and push image
    log_info "Building container image..."
    cd "$APP_DIR"
    IMAGE_TAG=$(git rev-parse --short HEAD 2>/dev/null || echo "latest")
    docker build -t "$ACR_NAME.azurecr.io/secure-api:$IMAGE_TAG" .
    docker push "$ACR_NAME.azurecr.io/secure-api:$IMAGE_TAG"

    # Apply Kubernetes manifests
    log_info "Applying Kubernetes manifests..."
    cd "$K8S_DIR"

    # Create namespace
    kubectl apply -f namespace.yaml

    # Apply other manifests
    kubectl apply -f serviceaccount.yaml
    kubectl apply -f secrets.yaml
    kubectl apply -f networkpolicy.yaml
    kubectl apply -f service.yaml

    # Update deployment with correct image
    sed "s|\${ACR_NAME}|$ACR_NAME|g; s|\${IMAGE_TAG}|$IMAGE_TAG|g" deployment.yaml | kubectl apply -f -

    kubectl apply -f hpa.yaml
    kubectl apply -f ingress.yaml

    # Wait for deployment
    log_info "Waiting for deployment to be ready..."
    kubectl rollout status deployment/secure-api -n secure-app --timeout=300s

    log_success "Application deployed successfully!"

    # Show status
    kubectl get pods -n secure-app
}

# =============================================================================
# FULL DEPLOYMENT
# =============================================================================

deploy_all() {
    check_prerequisites
    terraform_init
    terraform_plan
    terraform_apply
    deploy_app

    log_success "Full deployment complete!"
    echo ""
    log_info "Next steps:"
    echo "  1. Configure Jenkins: $(terraform -chdir="$TERRAFORM_DIR" output -raw jenkins_url 2>/dev/null || echo 'http://<jenkins-ip>:8080')"
    echo "  2. Access application: $(terraform -chdir="$TERRAFORM_DIR" output -raw appgw_fqdn 2>/dev/null || echo 'http://<appgw-ip>')"
    echo "  3. Monitor with Grafana: kubectl port-forward svc/grafana 3000:3000 -n monitoring"
}

# =============================================================================
# MAIN
# =============================================================================

case "$1" in
    init)
        check_prerequisites
        terraform_init
        ;;
    plan)
        check_prerequisites
        terraform_plan
        ;;
    apply)
        check_prerequisites
        terraform_apply
        ;;
    destroy)
        check_prerequisites
        terraform_destroy
        ;;
    app)
        check_prerequisites
        deploy_app
        ;;
    all)
        deploy_all
        ;;
    *)
        echo "Usage: $0 {init|plan|apply|destroy|app|all}"
        echo ""
        echo "Commands:"
        echo "  init      Initialize Terraform"
        echo "  plan      Run Terraform plan"
        echo "  apply     Apply Terraform configuration"
        echo "  destroy   Destroy all resources"
        echo "  app       Deploy application to AKS"
        echo "  all       Full deployment (infrastructure + application)"
        exit 1
        ;;
esac
