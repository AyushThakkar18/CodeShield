# CodeShield Security Scanner

A developer-focused security scanning tool that analyzes public GitHub repositories for vulnerabilities, secrets, and dependency issues.

## Project Structure

```
codeshield-security-scanner/
├── frontend/                 # React TypeScript frontend
│   ├── src/
│   │   ├── components/      # React components
│   │   ├── services/        # API service layer
│   │   └── types/           # TypeScript type definitions
│   ├── public/              # Static assets
│   ├── package.json         # Frontend dependencies
│   ├── tailwind.config.js   # Tailwind CSS configuration
│   └── Dockerfile           # Frontend container configuration
├── backend/                 # FastAPI Python backend
│   ├── app/
│   │   ├── api/            # API endpoints
│   │   ├── models/         # Data models
│   │   └── services/       # Business logic services
│   ├── tests/              # Backend tests
│   ├── requirements.txt    # Python dependencies
│   └── Dockerfile          # Backend container configuration
├── docker-compose.yml      # Production deployment
├── docker-compose.dev.yml  # Development environment
└── README.md              # This file
```

## Quick Start

### Development Environment

1. Clone the repository
2. Run the development environment:
   ```bash
   docker-compose -f docker-compose.dev.yml up --build
   ```
3. Access the application:
   - Frontend: http://localhost:3000
   - Backend API: http://localhost:8000


## Features

- **Static Code Analysis**: Uses Bandit to detect Python security vulnerabilities
- **Dependency Scanning**: Uses Trivy to identify vulnerable dependencies and CVEs
- **Secret Detection**: Uses detect-secrets to find hardcoded credentials and API keys
- **Report Generation**: Provides both PDF and JSON report formats
- **Real-time Progress**: Shows scanning progress with live updates
- **Responsive UI**: Modern React interface with Tailwind CSS

## Requirements

- Docker and Docker Compose
- Git (for repository cloning)
- Internet connection (for GitHub repository access)

## Security Features

- Automatic cleanup of temporary files
- No permanent storage of source code
- Resource limits and timeout handling
- Input validation and sanitization
