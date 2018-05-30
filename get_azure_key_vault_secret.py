import os
import sys
import requests

# Key Vault name and at least one secret name must be specified
assert len(sys.argv) >= 3

# Key Vault name
key_vault_name = sys.argv[1]

# Names of each secret to be retrieved from the Key Vault
secret_name_list = [name for name in sys.argv[2:]]

# Issue request to MSI endpoint to get access token for Key Vault
try:
    access_token_url = 'http://169.254.169.254/metadata/identity/oauth2/token?api-version' \
                       '=2018-02-01&resource=https%3A%2F%2Fvault.azure.net'
    access_token = requests.get(
        access_token_url,
        headers={"Metadata" : "true"}
    ).json()['access_token']
except OSError as e:
    sys.exit("Failed to request Azure access token. " +
             "Are you running script on an Azure Linux VM?\n%s" % e)
except ValueError as e:
    sys.exit("Access token response body does not contain valid JSON. " +
             "Contact maintainer.\n%s" % e)
except KeyError as e:
    sys.exit("The format of the access token json response has changed. " +
             "Contact maintainer. Key not found: \n%s" % e)

# Use access token to authenticate to the Key Vault and read each secret from it
for secret_name in secret_name_list:
    read_secret_url = 'https://%svault.vault.azure.net/secrets/%s?api-version' \
                      '=2016-10-01' % (key_vault_name, secret_name)
    try:
        read_secret_response = requests.get(
            read_secret_url,
            headers={"Authorization": "Bearer %s" % str(access_token)}
        )
        secret_value = read_secret_response.json()['value']
    except OSError as e:
        sys.exit("Failed to request Azure access token. " +
                 "Are you running script on an Azure Linux VM?\n%s" % e)
    except KeyError as e:
        sys.exit("Could not access secret in Key Vault. Verify the VM " +
                 "was granted access to vault with name '%s' " % key_vault_name +
                 "and that a key with name '%s' exists in it." % secret_name)
    try:
        # create .txt of secret value contents with rw permissions
        # restricted to the current user. File is located in home
        # directory with a file name maching the secret name.
        # After creation, cloud-init can use the file as it sees fit.
        file_path = os.path.join(os.path.expanduser("~"),
                                 secret_name+".txt")
        if os.path.isfile(file_path):
            os.remove(file_path)
        original_umask = os.umask(0o177)  # 0o777 ^ 0o600
        try:
            with os.fdopen(
                    os.open(
                        file_path, os.O_WRONLY | os.O_CREAT, 0o600
                    ), 'w'
            ) as handle:
                handle.write(secret_value)
        finally:
            os.umask(original_umask)
        print("Created file with secret value contents: '%s'" % file_path)
    except Exception as e:
        sys.exit("Able to access secret: %s, but could not " +
                 "create text file with secret value.\n%s" % e)
