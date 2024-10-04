# My Flask Boilerplate

A lightweight boilerplate to kickstart your Flask applications with a clean and organized structure.

## Features

- **Easy Setup**: Quickly get started with Flask development.
- **Modular Structure**: Organized directory layout for scalability.
- **Configuration Management**: Easily manage different environments (development, testing, production).
- **Basic Authentication**: Integrated user authentication setup.
- **Sample Routes**: Pre-defined routes for demonstration.

## Getting Started

### Prerequisites

- Python 3.x
- pip

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yg1222/yg-flask-boilerplate.git
   cd yg-flask-boilerplate

2. Create a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows use `venv\Scripts\activate`

3. Install dependencies:
   ```bash
   pip install -r requirements.txt

4. Setup your environment variables. Check config.py

Running the App
To run the application, use:
   ```bash
   FLASK_APP=wsgi.py flask run

