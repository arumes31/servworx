# servworx

![Build and Publish Docker Image](https://github.com/arumes31/servworx/actions/workflows/docker-publish.yml/badge.svg)
![Daily Security Scan](https://github.com/arumes31/servworx/actions/workflows/security-scan.yml/badge.svg)
![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)

servworx is a web-based service monitoring and auto-restart tool for Docker containers. It allows you to monitor the availability of specified website URLs and automatically restart associated Docker containers if a service goes down after a configured number of retries. The application provides a user-friendly web interface for configuration, status overview, and basic management of your monitored services.

<img width="881" height="699" alt="grafik" src="https://github.com/user-attachments/assets/29a77b6f-32a1-4bbc-a90a-c82e19a24f05" />
<img width="1243" height="815" alt="grafik" src="https://github.com/user-attachments/assets/7d77d667-75c7-4e3c-81f1-02eae578d011" />



## Features

- **Service Monitoring**: Continuously checks the availability of configured website URLs.
- **Automated Container Restart**: If a service becomes unreachable after a defined number of retries, servworx can automatically restart its associated Docker containers.
- **Configurable Services**: Easily add, update, and delete services directly from the web interface. Each service can have its own monitoring parameters (URL, container names, retry count, interval, grace period, accepted HTTP status codes).
- **Grace Period**: Prevents immediate restarts after a service comes online or after a manual restart, allowing it time to stabilize.
- **User Authentication**: Secure login system with password change functionality.
- **Real-time Status**: View the current status of all monitored services (Up/Down, last failure, uptime/downtime duration).
- **Container Log Viewing**: Access the last 10 lines of logs for associated containers directly from the web interface.
- **Pause/Resume Monitoring**: Temporarily pause or resume monitoring for individual services.
- **Force Restart**: Manually trigger a restart of a service's containers.
- **Docker Integration**: Leverages Docker for container management and restarts.

## Getting Started

These instructions will get you a copy of the project up and running on your local machine for development and testing purposes.

### Prerequisites

- [Docker](https://docs.docker.com/get-docker/) installed and running.
- [Docker Compose](https://docs.docker.com/compose/install/) installed.

### Installation and Setup

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/your-username/servworx.git
    cd servworx
    ```

2.  **Build and run the Docker containers:**
    ```bash
    docker-compose up --build -d
    ```
    This command will build the Docker image for servworx and start the service in detached mode.

3.  **Access the Web Interface:**
    Open your web browser and navigate to `http://localhost:7676`.

    The default login credentials are:
    - Username: `admin`
    - Password: `changeme` (You will be prompted to change this upon first login).

### Using Pre-built Docker Image

If you prefer to use the pre-built Docker image from the GitHub Container Registry (GHCR) instead of building it locally, you can use the provided example configuration.

1.  **Run with the GHCR compose file:**
    ```bash
    docker-compose -f docker-compose.ghcr.example.yaml up -d
    ```

## Configuration

servworx stores its configuration in the `./config` directory, which is mounted as a volume into the Docker container.

-   `config.json`: Stores user credentials and service monitoring configurations.
-   `status.json`: Stores the current monitoring status of services.

You can manage services directly through the web interface.

## Project Structure

```
.
├── app.py                  # Flask application main entry point
├── requirements.txt        # Python dependencies
├── docker-compose.yaml     # Docker Compose configuration
├── Dockerfile              # Docker image build instructions
├── templates/              # Jinja2 HTML templates
│   ├── change_password.html
│   ├── config.html
│   └── login.html
└── README.md               # This README file
```

## Built With

-   [Flask](https://flask.palletsprojects.com/) - The web framework used
-   [Waitress](https://docs.pylonproject.org/projects/waitress/en/latest/) - WSGI server
-   [Requests](https://docs.python-requests.org/en/master/) - HTTP library
-   [Docker](https://www.docker.com/) - Containerization platform

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
