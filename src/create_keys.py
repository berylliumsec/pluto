import argparse
import logging
import subprocess
from pathlib import Path

# Set up logging
logging.basicConfig(
    level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s"
)

# Paths
src_directory = Path("pluto")
san_conf_path = src_directory / "san.cnf"
private_key_path = src_directory / "private.key"
certificate_path = src_directory / "certificate.pem"


def create_san_config_file(ip_address):
    """
    Create the SAN configuration file with specified IP address.
    """
    try:
        san_config_content = f"""[ san ]
subjectAltName = @alt_names

[ alt_names ]
IP.1 = {ip_address}
"""
        src_directory.mkdir(parents=True, exist_ok=True)  # Ensure directory exists
        with open(san_conf_path, "w") as file:
            file.write(san_config_content)
        logging.info("SAN configuration file created successfully.")
    except Exception as e:
        logging.error(f"Failed to create SAN configuration file: {e}")


def generate_certificate(ip_address):
    """
    Generate SSL certificate using OpenSSL with the SAN configuration.
    """
    try:
        # Use <(cat ...) trick with dynamically inserted IP address
        openssl_cmd = (
            f"openssl req -x509 -nodes -days 365 -newkey rsa:2048 "
            f"-keyout {private_key_path} -out {certificate_path} "
            f'-subj "/CN=myserver" -extensions san '
            f'-config <(cat /etc/ssl/openssl.cnf <(printf "\\n[ san ]\\nsubjectAltName=@alt_names\\n[alt_names]\\nIP.1={ip_address}"))'
        )
        subprocess.run(openssl_cmd, shell=True, check=True, executable="/bin/bash")
        logging.info("SSL certificate generated successfully.")
    except subprocess.CalledProcessError as e:
        logging.error(f"OpenSSL command failed: {e}")
    except Exception as e:
        logging.error(f"Failed to generate certificate: {e}")


def verify_certificate():
    """
    Verify the certificate to ensure it contains the correct SAN entries.
    """
    try:
        verify_cmd = f'openssl x509 -in {certificate_path} -text -noout | grep -A1 "Subject Alternative Name"'
        result = subprocess.run(
            verify_cmd,
            shell=True,
            text=True,
            check=True,
            stdout=subprocess.PIPE,
            executable="/bin/bash",
        )
        logging.info("Certificate verification output:")
        logging.info(result.stdout)
    except subprocess.CalledProcessError as e:
        logging.error(f"Verification command failed: {e}")
    except Exception as e:
        logging.error(f"Failed to verify certificate: {e}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Generate and verify an SSL certificate with a custom SAN IP."
    )
    parser.add_argument(
        "--ip", default="192.168.1.155", help="The IP address to use in the SAN field."
    )

    args = parser.parse_args()
    ip_address = args.ip

    create_san_config_file(ip_address)
    generate_certificate(ip_address)
    verify_certificate()
