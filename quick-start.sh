#!/bin/bash

# ============================================================================
# Sky Genesis Enterprise API - Quick Start Script
# ============================================================================

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
COMPOSE_FILE="infrastructure/docker/docker-compose.all-in-one.yml"
PROJECT_NAME="sky-genesis"

echo -e "${BLUE}========================================"
echo -e "${BLUE}Sky Genesis Enterprise API - Quick Start"
echo -e "${BLUE}========================================${NC}"

# Function to check if Docker is running
check_docker() {
    if ! docker info > /dev/null 2>&1; then
        echo -e "${RED}ERROR: Docker is not running. Please start Docker first.${NC}"
        exit 1
    fi
    echo -e "${GREEN}✓ Docker is running${NC}"
}

# Function to check if Docker Compose is available
check_docker_compose() {
    if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
        echo -e "${RED}ERROR: Docker Compose is not installed.${NC}"
        exit 1
    fi
    echo -e "${GREEN}✓ Docker Compose is available${NC}"
}

# Function to stop existing containers
stop_existing() {
    echo -e "${YELLOW}Stopping existing containers...${NC}"
    
    if command -v docker-compose &> /dev/null; then
        docker-compose -f $COMPOSE_FILE -p $PROJECT_NAME down --remove-orphans || true
    else
        docker compose -f $COMPOSE_FILE -p $PROJECT_NAME down --remove-orphans || true
    fi
    
    echo -e "${GREEN}✓ Existing containers stopped${NC}"
}

# Function to build and start containers
start_services() {
    echo -e "${BLUE}Building and starting services...${NC}"
    
    if command -v docker-compose &> /dev/null; then
        docker-compose -f $COMPOSE_FILE -p $PROJECT_NAME up --build -d
    else
        docker compose -f $COMPOSE_FILE -p $PROJECT_NAME up --build -d
    fi
    
    echo -e "${GREEN}✓ Services started successfully${NC}"
}

# Function to wait for services to be ready
wait_for_services() {
    echo -e "${BLUE}Waiting for services to be ready...${NC}"
    
    # Wait for API
    echo -e "${YELLOW}Waiting for API service...${NC}"
    timeout=120
    while [ $timeout -gt 0 ]; do
        if curl -f http://localhost:8080/api/v1/health > /dev/null 2>&1; then
            echo -e "${GREEN}✓ API service is ready${NC}"
            break
        fi
        sleep 2
        timeout=$((timeout - 2))
    done
    
    if [ $timeout -le 0 ]; then
        echo -e "${RED}ERROR: API service failed to start within 2 minutes${NC}"
        return 1
    fi
    
    # Wait for Frontend
    echo -e "${YELLOW}Waiting for Frontend service...${NC}"
    timeout=60
    while [ $timeout -gt 0 ]; do
        if curl -f http://localhost:3000 > /dev/null 2>&1; then
            echo -e "${GREEN}✓ Frontend service is ready${NC}"
            break
        fi
        sleep 2
        timeout=$((timeout - 2))
    done
    
    if [ $timeout -le 0 ]; then
        echo -e "${YELLOW}WARNING: Frontend service may still be starting${NC}"
    fi
}

# Function to show service URLs
show_urls() {
    echo -e ""
    echo -e "${GREEN}========================================"
    echo -e "${GREEN}Services are running!${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo -e ""
    echo -e "${BLUE}🚀 API Backend:${NC}"
    echo -e "   Health: ${YELLOW}http://localhost:8080/api/v1/health${NC}"
    echo -e "   API Keys: ${YELLOW}http://localhost:8080/api/v1/keys${NC}"
    echo -e "   Docs: ${YELLOW}http://localhost:8080/docs${NC}"
    echo -e ""
    echo -e "${BLUE}🎛️  Frontend Admin:${NC}"
    echo -e "   Application: ${YELLOW}http://localhost:3000${NC}"
    echo -e ""
    echo -e "${BLUE}🔑 SSH Access:${NC}"
    echo -e "   SSH: ${YELLOW}ssh -p 2222 apiuser@localhost${NC}"
    echo -e ""
    echo -e "${BLUE}🗄️  Database:${NC}"
    echo -e "   PostgreSQL: ${YELLOW}localhost:5432${NC}"
    echo -e "   User: ${YELLOW}postgres${NC}"
    echo -e "   Password: ${YELLOW}password${NC}"
    echo -e "   Database: ${YELLOW}api_service${NC}"
    echo -e ""
    echo -e "${BLUE}📊 Cache:${NC}"
    echo -e "   Redis: ${YELLOW}localhost:6379${NC}"
    echo -e "   Password: ${YELLOW}redis_password${NC}"
    echo -e ""
}

# Function to show logs
show_logs() {
    echo -e "${BLUE}Showing logs...${NC}"
    if command -v docker-compose &> /dev/null; then
        docker-compose -f $COMPOSE_FILE -p $PROJECT_NAME logs -f
    else
        docker compose -f $COMPOSE_FILE -p $PROJECT_NAME logs -f
    fi
}

# Function to stop services
stop_services() {
    echo -e "${YELLOW}Stopping services...${NC}"
    if command -v docker-compose &> /dev/null; then
        docker-compose -f $COMPOSE_FILE -p $PROJECT_NAME down
    else
        docker compose -f $COMPOSE_FILE -p $PROJECT_NAME down
    fi
    echo -e "${GREEN}✓ Services stopped${NC}"
}

# Main execution
main() {
    case "${1:-start}" in
        "start"|"up")
            check_docker
            check_docker_compose
            stop_existing
            start_services
            wait_for_services
            show_urls
            ;;
        "stop"|"down")
            stop_services
            ;;
        "restart")
            stop_services
            sleep 2
            main start
            ;;
        "logs"|"log")
            show_logs
            ;;
        "status")
            if command -v docker-compose &> /dev/null; then
                docker-compose -f $COMPOSE_FILE -p $PROJECT_NAME ps
            else
                docker compose -f $COMPOSE_FILE -p $PROJECT_NAME ps
            fi
            ;;
        "clean")
            echo -e "${YELLOW}Cleaning up containers and volumes...${NC}"
            stop_services
            if command -v docker-compose &> /dev/null; then
                docker-compose -f $COMPOSE_FILE -p $PROJECT_NAME down -v --remove-orphans
            else
                docker compose -f $COMPOSE_FILE -p $PROJECT_NAME down -v --remove-orphans
            fi
            echo -e "${GREEN}✓ Cleanup completed${NC}"
            ;;
        "help"|"-h"|"--help")
            echo -e "${BLUE}Sky Genesis Enterprise API - Quick Start Script${NC}"
            echo -e ""
            echo -e "${YELLOW}Usage: $0 [command]${NC}"
            echo -e ""
            echo -e "${YELLOW}Commands:${NC}"
            echo -e "  start, up     Start all services (default)"
            echo -e "  stop, down    Stop all services"
            echo -e "  restart       Restart all services"
            echo -e "  logs, log     Show service logs"
            echo -e "  status        Show service status"
            echo -e "  clean         Stop services and remove volumes"
            echo -e "  help          Show this help message"
            echo -e ""
            echo -e "${YELLOW}Examples:${NC}"
            echo -e "  $0                # Start services"
            echo -e "  $0 start          # Start services"
            echo -e "  $0 logs           # Show logs"
            echo -e "  $0 stop           # Stop services"
            echo -e ""
            ;;
        *)
            echo -e "${RED}Unknown command: $1${NC}"
            echo -e "Use '$0 help' for usage information"
            exit 1
            ;;
    esac
}

# Run main function with all arguments
main "$@"