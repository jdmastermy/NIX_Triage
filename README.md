# NIX_Triage
Just a python script to parse as much as NIX based artefacts for Incident Response. It is developed to cover both LINUX and MAC OSX artefacts

## How to Use
Instructions to Use the Script:

- Save the script as nix_triage.py.
- Open a terminal or command prompt.
- Navigate to the directory where the script is saved.
- Run the script using the following command:

   `python nix_triage.py -o /path/to/output -u /home/username -f /path/to/specific/file`

# Help Output
To see the help message and usage instructions, you can run:

`python nix_triage.py --help`

Command Line Flags and Options

    -h, --help: Show the help message and exit.
    -o, --output-dir: Specify the output directory for JSON and CSV files. Default is the current directory.
    -u, --user-home: Specify the user home directory to collect bash history and recent files. Default is /home/user.
    -f, --file-path: Specify a file path to collect file metadata. Default is /path/to/file.
