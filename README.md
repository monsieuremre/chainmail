# Chainmail

## About The Project

Chainmail is a script for hardening your Debian GNU/Linux workstation. It takes its name from the type of armor consisting of metal rings linked together, and is an analogy to the protections you will get by herdening your system. This projects covers the following content,

* Kernel Settings Hardening
* Kernel Modules Hardening
* Network Hardening
* Disabling Core Dumps
* Hardened Boot Parameters
* Firewall Configuration
* Entropy Improvements
* Brute Force Protection
* Hardening APT
* Access Rights Hardening
* Improving Mandatory Access Control
* Installing Various Packages for Security

## Before Getting Started 

This hardening script was developed on and for the latest release of Debian GNU/Linux codename Bookworm. That being said, it should also work on previous Debian releases with no problems. It should also work on the various GNU/Linux distributions that are based on Debian, like Ubuntu etc, but this was never tested. This script does not try to be a no-config just run and forget kind of automatic hardening, though for the most part it is exactly that. Regardless, discretion is recommended. You will need to comment some stuff out. Needless to say, back up your sensitive data. Chances are you won't lose your data anyway, but take your precautions just in case. Necessary packages installations are handled within the script so you do not need to manually install anything prior.

## Usage

### Download the script and make it executable
```
wget https://raw.githubusercontent.com/monsieuremre/chainmail/master/chainmail.sh
chmod +x ./chainmail.sh
```

### Do your modifications or comment out parts
Some parts of the script needs further tuning depending on your setup. These are quite rudimentary and require you to know just some v    ery basic informtaion about your specific installation. If you are unwilling to do this fine tuning, just comment out these parts completely not to sacrifice any stability.

### Run the script
```
./chainmail.sh
```

## Sources

When preparing this script I used various tools and sources. The most notable tool I used is [Lynis](https://cisofy.com/lynis/). Notable resources I used are
* [Kicksecure Wiki](https://www.kicksecure.com/wiki/)
* [Kernel Self Protection Project](https://kernsec.org/wiki/)
* [Whonix Forums | Kernel Hardening - security-misc](https://forums.whonix.org/t/kernel-hardening-security-misc/7296/43)

## Contributing

The fact that anybody can contribute is what makes Free and Open Source Software the best tool to learn and create.
If you have any suggestions regarding the project, do not hesitate fork the repo and create a pull request.

## License

Chainmail is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version. 

See [LICENSE](LICENSE) for more details.

## Contact

If you need to contact me regarding the project for any reason, please open an issue or create a pull request.

Project Link: [https://github.com/monsieuremre/chainmail](https://github.com/monsieuremre/chainmail)
