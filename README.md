# "Phase 1" ~ Windows Auditing, Automated
This script will document your computer's current profile and take a few unproblematic steps to harden its configuration

**Warning** - this script is not yet ready for production usage, so please use it with caution.

### Methodology --
> The most successful enterprises maintain proper documentation of their systems/infastructure and is crucial in the event of an incident. 
> Unfortunately, garnering this documentation  has proven itself to be particularly time consuming and is prone to human error. 
> This script intends to ease the burden of auditing through automation.

### Phase 1 Options -- 
#### Audit Options
  * Users and Group Members  - (_inlcudes Domain Users, Remote Desktop Users, Service Accounts, and Active/Inactive Users_)
  * System Services, Processes, and Programs - (_includes activley running processes and services, and notes services that are not running under a standard system account, in addition to noting the installed programs on the system_)
  * Active Network Connections
  * Current Firewall Rule-set - (_will output the ACL list in tabular format_)
  * Scheduled Tasks - (_will audit current scheduled tasks and note any custom-made tasks that are persistent_)
  * Registry Run Keys - (_will audit pertinent registry keys that agents have commonly used for start-up persistence_)
  * Misc - (_will audit the host file, and the path enviornment variable_)


#### Basic System Hardening Options
  * Establishing Adminitrative Persistence 
  * Basic Network Security Configuration (_Includes Firewall Rule-set, Establishing Connection Logging, and disabling unneccessary network services_)
  * Disabling SMB, and or Remove System Access (_These are common entry-point and pivoting mechanisms, if they are not being used on the network, it is important to restrict access and disable them_)

## Usage --
1. Select to run either the GUI.exe, for an interactive window form of the program, or Phase1.exe for a command-line execution format.
#### The Application Window:
 ![Example Application Window](example\Phase1-GUI.png)

3. Choose whatever phase options suit your needs, as outlined above.
4. A Transcription of the audit will be placed in your current directory, as well as in the console.


 CONTACT: please refer any questions or comments regarding this script to @kogatana-x
