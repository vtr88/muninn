# Muninn Proxy

Muninn is a simple HTTPS proxy server implemented in C using OpenSSL. It allows you to intercept and modify HTTPS traffic for testing and debugging purposes. This README provides instructions on how to set up and use Muninn, including generating the required SSL/TLS certificates.

## Usage

### Building Muninn

To build Muninn, run the following command in your terminal:

```
make
```

This will compile the Muninn source code and generate the `muninn` executable.

### Generating SSL/TLS Certificates

Before running Muninn, you need to generate SSL/TLS certificates for the server. Follow these steps:

1. Generate a private key file:
   ```
   openssl genrsa -out key.pem 2048
   ```

2. Generate a certificate signing request (CSR):
   ```
   openssl req -new -key key.pem -out csr.pem
   ```

3. Generate a self-signed certificate using the CSR and private key:
   ```
   openssl x509 -req -days 365 -in csr.pem -signkey key.pem -out cert.pem
   ```

4. Generate a CA certificate (optional if you want to enable client authentication):
   ```
   openssl req -x509 -newkey rsa:2048 -keyout ca-key.pem -out ca-cert.pem -days 365
   ```

### Running Muninn

To run Muninn, execute the following command:

```
./muninn
```

By default, Muninn listens on port 13337 for incoming connections.

### Importing CA Certificate into Firefox

To use Muninn as an HTTPS proxy with client authentication, you'll need to import the CA certificate (`ca-cert.pem`) into Firefox. Here's how:

1. Open Firefox and click on the menu button (three horizontal lines) in the top-right corner.

2. Select **Preferences** from the dropdown menu.

3. In the Preferences window, click on **Privacy & Security** in the left sidebar.

4. Scroll down to the **Certificates** section and click on the **View Certificates** button.

5. In the Certificate Manager window, switch to the **Authorities** tab.

6. Click on the **Import** button.

7. Locate the `ca-cert.pem` file on your filesystem and click **Open**.

8. Check the box next to **Trust this CA to identify websites** and click **OK**.

9. You may be prompted to enter your system password to confirm the import.

10. Once imported, Firefox will trust certificates signed by the CA certificate, allowing Muninn to act as an HTTPS proxy with client authentication.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
