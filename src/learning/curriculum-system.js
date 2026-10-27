/**
 * EJII Learning Center — System Administration Academy Curriculum
 * Windows Administration, Windows Server & Active Directory, Linux Administration, Enterprise Operations.
 * 4 Courses, 12 Modules, 36 Substantive Lessons with Worked Examples, Scripts/Commands,
 * Best Practices, Knowledge Checks, and Lab Integrations.
 */

'use strict';

const SYSTEM_COURSES = [
  {
    id: 'windows-administration',
    trackId: 'system',
    slug: 'windows-administration',
    title: 'Windows Administration & PowerShell',
    subtitle: 'Kernel Architecture, Service Control Manager, Event Logs & Automation',
    description: 'Master practical Windows client and server administration, process forensics, NTFS access control, and PowerShell automation.',
    level: 'beginner',
    estimatedMinutes: 240,
    accent: '#0369A1',
    objectives: [
      'Explain Windows OS architecture, kernel vs user mode, processes, and service lifecycles.',
      'Configure NTFS permissions, inheritance, and calculate effective SMB share access.',
      'Automate system administration and hardware inventory using the PowerShell object pipeline.'
    ],
    moduleIds: ['sys-mod-win-core', 'sys-mod-win-security', 'sys-mod-win-powershell'],
    prerequisites: []
  },
  {
    id: 'windows-server',
    trackId: 'system',
    slug: 'windows-server',
    title: 'Windows Server & Active Directory',
    subtitle: 'AD DS Hierarchy, Kerberos Authentication, Group Policy & Enterprise Roles',
    description: 'Deploy, administer, and troubleshoot enterprise identity, Active Directory Domain Services, Group Policy Objects, and core infrastructure services.',
    level: 'intermediate',
    estimatedMinutes: 320,
    accent: '#1E40AF',
    objectives: [
      'Architect Active Directory domains, forests, organizational units, and security group nesting.',
      'Implement and troubleshoot Group Policy application using LSDOU precedence and gpresult.',
      'Administer enterprise AD-Integrated DNS zones and Windows DHCP failover clusters.'
    ],
    moduleIds: ['sys-mod-ad-core', 'sys-mod-ad-gpo', 'sys-mod-win-services'],
    prerequisites: ['windows-administration']
  },
  {
    id: 'linux-administration',
    trackId: 'system',
    slug: 'linux-administration',
    title: 'Linux Systems Administration',
    subtitle: 'FHS Filesystem, User Permissions, Systemd Daemons, Networking & SSH',
    description: 'Administer enterprise Linux servers: master the shell, file permissions, systemd service units, modern networking with iproute2, and SSH hardening.',
    level: 'intermediate',
    estimatedMinutes: 320,
    accent: '#D97706',
    objectives: [
      'Navigate the Filesystem Hierarchy Standard (FHS) and configure octal file permissions.',
      'Manage background services and troubleshoot crashes using systemctl and journalctl.',
      'Configure static IP routing, inspect socket endpoints with ss, and harden OpenSSH servers.'
    ],
    moduleIds: ['sys-mod-linux-core', 'sys-mod-linux-services', 'sys-mod-linux-networking'],
    prerequisites: ['windows-administration']
  },
  {
    id: 'enterprise-operations',
    trackId: 'system',
    slug: 'enterprise-operations',
    title: 'Enterprise Systems Operations & SRE',
    subtitle: 'Observability, 3-2-1 Backups, Disaster Recovery & Incident Management',
    description: 'Learn the principles of enterprise site reliability: metrics collection, staged patch management, backup recovery drills, and blameless incident triage.',
    level: 'advanced',
    estimatedMinutes: 300,
    accent: '#475569',
    objectives: [
      'Design comprehensive system telemetry collection and centralized audit log aggregation.',
      'Implement the 3-2-1 backup strategy and execute disaster recovery validation drills.',
      'Lead ITIL incident management triage and author actionable, blameless post-mortems.'
    ],
    moduleIds: ['sys-mod-ops-observability', 'sys-mod-ops-resilience', 'sys-mod-ops-incident'],
    prerequisites: ['windows-server', 'linux-administration']
  }
];

const SYSTEM_MODULES = [
  // Course 1 Modules
  {
    id: 'sys-mod-win-core',
    courseId: 'windows-administration',
    title: 'Module 1: Windows OS Architecture & Core Services',
    description: 'Operating system internals: kernel mode, service control manager, processes, and event logging.',
    lessonIds: ['sys-win-kernel-services', 'sys-win-task-process', 'sys-win-event-logs']
  },
  {
    id: 'sys-mod-win-security',
    courseId: 'windows-administration',
    title: 'Module 2: Users, Storage & Security Permissions',
    description: 'User access control, NTFS permissions, share permissions, and effective access calculations.',
    lessonIds: ['sys-win-local-accounts', 'sys-win-ntfs-permissions', 'sys-win-share-permissions']
  },
  {
    id: 'sys-mod-win-powershell',
    courseId: 'windows-administration',
    title: 'Module 3: PowerShell for Administrators',
    description: 'The PowerShell pipeline, object manipulation, filtering, and system diagnostics with WMI/CIM.',
    lessonIds: ['sys-ps-cmdlet-basics', 'sys-ps-filtering-formatting', 'sys-ps-system-diagnostics']
  },

  // Course 2 Modules
  {
    id: 'sys-mod-ad-core',
    courseId: 'windows-server',
    title: 'Module 1: Active Directory Domain Services',
    description: 'Domain and forest architecture, organizational units, and AGDLP security group nesting.',
    lessonIds: ['sys-ad-forest-domain', 'sys-ad-ou-hierarchy', 'sys-ad-groups-users']
  },
  {
    id: 'sys-mod-ad-gpo',
    courseId: 'windows-server',
    title: 'Module 2: Group Policy & Enterprise Authentication',
    description: 'LSDOU Group Policy precedence, Kerberos V5 ticket mechanics, and gpresult triage.',
    lessonIds: ['sys-gpo-processing-order', 'sys-kerberos-ntlm', 'sys-gpo-troubleshooting']
  },
  {
    id: 'sys-mod-win-services',
    courseId: 'windows-server',
    title: 'Module 3: Core Enterprise Infrastructure',
    description: 'Active Directory-Integrated DNS, Windows DHCP failover scopes, and FSRM storage.',
    lessonIds: ['sys-ad-integrated-dns', 'sys-win-dhcp-failover', 'sys-fsrm-storage-pool']
  },

  // Course 3 Modules
  {
    id: 'sys-mod-linux-core',
    courseId: 'linux-administration',
    title: 'Module 1: Linux Filesystem & Terminal Fundamentals',
    description: 'FHS directory structure, octal permissions, user/group ownership, and text pipeline processing.',
    lessonIds: ['sys-linux-fhs-navigation', 'sys-linux-users-permissions', 'sys-linux-text-processing']
  },
  {
    id: 'sys-mod-linux-services',
    courseId: 'linux-administration',
    title: 'Module 2: Process & Service Management',
    description: 'systemd service units, targets, journalctl log inspection, package managers, and storage mounts.',
    lessonIds: ['sys-linux-systemd-units', 'sys-linux-package-management', 'sys-linux-cron-storage']
  },
  {
    id: 'sys-mod-linux-networking',
    courseId: 'linux-administration',
    title: 'Module 3: Linux Networking & Remote Access',
    description: 'Modern iproute2 networking, socket triage with ss, and OpenSSH cryptographic hardening.',
    lessonIds: ['sys-linux-ip-routing', 'sys-linux-socket-diagnostics', 'sys-linux-ssh-hardening']
  },

  // Course 4 Modules
  {
    id: 'sys-mod-ops-observability',
    courseId: 'enterprise-operations',
    title: 'Module 1: Observability, Metrics & Patching',
    description: 'System telemetry, synthetic health probes, SIEM log ingestion, and staged patching rings.',
    lessonIds: ['sys-ops-monitoring-metrics', 'sys-ops-log-aggregation', 'sys-ops-patch-management']
  },
  {
    id: 'sys-mod-ops-resilience',
    courseId: 'enterprise-operations',
    title: 'Module 2: Backup, Disaster Recovery & High Availability',
    description: 'The 3-2-1 backup strategy, RTO/RPO objectives, restore validation drills, and failover clustering.',
    lessonIds: ['sys-ops-backup-321', 'sys-ops-restore-validation', 'sys-ops-ha-failover']
  },
  {
    id: 'sys-mod-ops-incident',
    courseId: 'enterprise-operations',
    title: 'Module 3: Incident Management & Operational Runbooks',
    description: 'ITIL incident response workflows, structured system diagnostics, and blameless post-mortems.',
    lessonIds: ['sys-ops-incident-lifecycle', 'sys-ops-troubleshooting-methodology', 'sys-ops-runbook-documentation']
  }
];

const SYSTEM_LESSONS = [
  // --- Course 1: Windows Administration ---
  // Module 1.1: Core
  {
    id: 'sys-win-kernel-services',
    courseId: 'windows-administration',
    moduleId: 'sys-mod-win-core',
    trackId: 'system',
    slug: 'windows-kernel-services-architecture',
    title: 'Windows Architecture: Kernel vs User Mode & Services',
    difficulty: 'beginner',
    estimatedMinutes: 20,
    objectives: [
      'Contrast User Mode (Ring 3) isolation with Kernel Mode (Ring 0) execution.',
      'Explain the Service Control Manager (services.exe) and service startup types.',
      'Diagnose stopped or hung Windows services using sc.exe and PowerShell.'
    ],
    sections: [
      {
        type: 'text',
        heading: 'The Dual-Ring Security Boundary',
        content: 'Windows NT architecture enforces a strict hardware-backed division between User Mode (Ring 3) and Kernel Mode (Ring 0). Standard user applications (browsers, word processors, shells) run in isolated virtual address spaces in User Mode. If an application crashes or suffers a memory violation, only that single process terminates. In contrast, Kernel Mode houses the executive, microkernel, hardware abstraction layer (HAL), and device drivers. A kernel crash or driver bug results in a BugCheck (Blue Screen of Death / BSOD).'
      },
      {
        type: 'table',
        heading: 'Windows Architecture Comparison',
        headers: ['Mode', 'Components', 'Hardware Access', 'Failure Impact'],
        rows: [
          ['User Mode (Ring 3)', 'Applications, Win32 subsystems, Service host processes (svchost)', 'No direct access; mediated via Windows API / System Calls', 'Isolated process termination; OS remains stable'],
          ['Kernel Mode (Ring 0)', 'NTOSKRNL.EXE, HAL.DLL, Graphics driver (win32k.sys), Hardware drivers', 'Unrestricted read/write access to physical CPU and RAM', 'Immediate BugCheck (BSOD) memory dump']
        ]
      },
      {
        type: 'code',
        language: 'powershell',
        title: 'Managing Windows Services via PowerShell',
        content: `# Query service status and startup type
Get-Service -Name "Spooler" | Select-Object Name, Status, StartType

# Stop a malfunctioning service gracefully
Stop-Service -Name "Spooler" -Force

# Change service startup type to Disabled
Set-Service -Name "Spooler" -StartupType Disabled`
      }
    ],
    quizId: 'quiz-windows-administration',
    labIds: ['sys-powershell-sandbox'],
    prevLessonId: null,
    nextLessonId: 'sys-win-task-process'
  },
  {
    id: 'sys-win-task-process',
    courseId: 'windows-administration',
    moduleId: 'sys-mod-win-core',
    trackId: 'system',
    slug: 'process-management-handles-threads',
    title: 'Task Manager, Sysinternals Process Explorer & Handles',
    difficulty: 'beginner',
    estimatedMinutes: 25,
    objectives: [
      'Explain the relationship between processes, execution threads, and kernel handles.',
      'Use Sysinternals Process Explorer to investigate locked files and parent-child trees.',
      'Identify memory leaks and high CPU utilization in enterprise applications.'
    ],
    sections: [
      {
        type: 'text',
        heading: 'Processes as Resource Containers',
        content: 'In Windows, a process is not a unit of code execution; a process is a secure resource container. It owns a private virtual address space, an executable image, access tokens, and a handle table. THREADS are the actual units of execution dispatched by the CPU scheduler. HANDLES are kernel pointers to system resources (files, registry keys, network sockets, mutexes).'
      },
      {
        type: 'callout',
        tone: 'tip',
        title: 'Diagnosing "File Is in Use" Errors',
        content: 'When Windows reports "The action can\'t be completed because the file is open in another program", open Sysinternals Process Explorer, press Ctrl+F (Find Handle or DLL), type the locked file name, and it instantly reveals the exact Process ID holding the open kernel handle!'
      },
      {
        type: 'code',
        language: 'powershell',
        title: 'PowerShell Process Triage',
        content: `# Find the top 5 CPU-consuming processes
Get-Process | Sort-Object CPU -Descending | Select-Object -First 5 Id, ProcessName, CPU, WorkingSet64

# Inspect modules loaded by a specific process
(Get-Process -Id 1420).Modules | Select-Object ModuleName, FileName`
      }
    ],
    quizId: 'quiz-windows-administration',
    labIds: ['sys-powershell-sandbox'],
    prevLessonId: 'sys-win-kernel-services',
    nextLessonId: 'sys-win-event-logs'
  },
  {
    id: 'sys-win-event-logs',
    courseId: 'windows-administration',
    moduleId: 'sys-mod-win-core',
    trackId: 'system',
    slug: 'event-viewer-system-security-application',
    title: 'Windows Event Viewer: System, Application & Security',
    difficulty: 'beginner',
    estimatedMinutes: 25,
    objectives: [
      'Navigate the primary Windows Event Log channels (System, Application, Security).',
      'Identify key security and operational Event IDs (4624, 4625, 7036, 1074).',
      'Filter and query event logs programmatically with Get-WinEvent.'
    ],
    sections: [
      {
        type: 'text',
        heading: 'The System Audit Record',
        content: 'Windows Event Viewer records system alerts, software crashes, and security audit trails into structured XML-backed .evtx files. Unlike plain text logs, Windows events contain structured metadata including Event ID, Provider Name, Severity Level, Computer, and Security User SID.'
      },
      {
        type: 'table',
        heading: 'Essential Windows Event IDs for System Administrators',
        headers: ['Event ID', 'Log Channel', 'Event Description', 'Operational Significance'],
        rows: [
          ['4624', 'Security', 'Successful Account Logon', 'Verifies user authentication (Logon Type 2=Interactive, 3=Network, 10=RDP)'],
          ['4625', 'Security', 'Failed Account Logon', 'Crucial for detecting brute-force password guessing attacks'],
          ['7036', 'System', 'Service State Change', 'Records when a service started, stopped, or crashed'],
          ['1074', 'System', 'System Shutdown / Restart', 'Identifies who initiated a server reboot and the reported reason code'],
          ['4720', 'Security', 'User Account Created', 'Audit record for user provisioning']
        ]
      },
      {
        type: 'code',
        language: 'powershell',
        title: 'Querying Event Logs with PowerShell FilterHashtable',
        content: `# Query the last 10 failed login attempts (Event ID 4625)
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id = 4625
} -MaxEvents 10 | Select-Object TimeCreated, Message`
      }
    ],
    quizId: 'quiz-windows-administration',
    labIds: ['sys-powershell-sandbox'],
    prevLessonId: 'sys-win-task-process',
    nextLessonId: 'sys-win-local-accounts'
  },

  // Module 1.2: Users & Security
  {
    id: 'sys-win-local-accounts',
    courseId: 'windows-administration',
    moduleId: 'sys-mod-win-security',
    trackId: 'system',
    slug: 'local-users-groups-uac',
    title: 'Local Accounts, Built-in Groups & User Account Control (UAC)',
    difficulty: 'beginner',
    estimatedMinutes: 20,
    objectives: [
      'Manage local user accounts and built-in security groups (Administrators, Users, Backup Operators).',
      'Explain User Account Control (UAC) token splitting and privilege elevation.',
      'Apply the Principle of Least Privilege in workstation management.'
    ],
    sections: [
      {
        type: 'text',
        heading: 'Local Security Authority & Security Identifiers (SIDs)',
        content: 'Every Windows user account is assigned a globally unique Security Identifier (SID), such as S-1-5-21-...-1001. Even if you rename an account from "John" to "Sarah", the SID remains constant. The Local Security Authority Subsystem Service (LSASS) validates credentials against the Security Account Manager (SAM) database.'
      },
      {
        type: 'callout',
        tone: 'info',
        title: 'How UAC Token Splitting Works',
        content: 'When an administrator logs on to Windows, UAC creates TWO access tokens: a Standard User token (filtered) and an Administrative token (full privileges). Applications launch with the standard token by default. Only when an administrative task is initiated does Windows trigger the UAC prompt, temporarily activating the high-integrity token.'
      }
    ],
    quizId: 'quiz-windows-administration',
    labIds: ['sys-powershell-sandbox'],
    prevLessonId: 'sys-win-event-logs',
    nextLessonId: 'sys-win-ntfs-permissions'
  },
  {
    id: 'sys-win-ntfs-permissions',
    courseId: 'windows-administration',
    moduleId: 'sys-mod-win-security',
    trackId: 'system',
    slug: 'ntfs-permissions-inheritance-deny',
    title: 'NTFS Permissions: Inheritance & Explicit Deny Precedence',
    difficulty: 'beginner',
    estimatedMinutes: 25,
    objectives: [
      'Differentiate Basic permissions (Read, Write, Modify, Full Control) from Advanced permissions.',
      'Explain permission inheritance and how to safely disable inheritance with copy vs remove.',
      'Master the evaluation order: Explicit Deny > Explicit Allow > Inherited Deny > Inherited Allow.'
    ],
    sections: [
      {
        type: 'text',
        heading: 'The Windows File System Access Control Engine',
        content: 'NTFS (New Technology File System) secures files and folders using Discretionary Access Control Lists (DACLs). A DACL consists of Access Control Entries (ACEs) specifying whether a particular user or group SID is allowed or denied specific rights.'
      },
      {
        type: 'table',
        heading: 'NTFS Permission Evaluation Hierarchy',
        headers: ['Precedence Level', 'Rule Type', 'Evaluation Behavior'],
        rows: [
          ['1 (Highest)', 'Explicit Deny', 'Directly applied to the file/folder; immediately terminates evaluation and denies access.'],
          ['2', 'Explicit Allow', 'Directly applied to the file/folder; grants access if no explicit deny exists.'],
          ['3', 'Inherited Deny', 'Inherited from parent folder; blocks access unless overridden by explicit child allow.'],
          ['4 (Lowest)', 'Inherited Allow', 'Inherited from parent folder; grants access only if no deny exists anywhere.']
        ]
      },
      {
        type: 'callout',
        tone: 'warning',
        title: 'Best Practice: Avoid Explicit Deny',
        content: 'Experienced system administrators avoid using explicit "Deny" ACEs whenever possible. Deny rules override group memberships and easily produce accidental lockouts. Instead, control access cleanly by granting Allow permissions only to the specific authorized groups.'
      }
    ],
    quizId: 'quiz-windows-administration',
    labIds: ['sys-active-directory-lab'],
    prevLessonId: 'sys-win-local-accounts',
    nextLessonId: 'sys-win-share-permissions'
  },
  {
    id: 'sys-win-share-permissions',
    courseId: 'windows-administration',
    moduleId: 'sys-mod-win-security',
    trackId: 'system',
    slug: 'smb-share-permissions-effective-access',
    title: 'SMB File Sharing & Effective Access Calculations',
    difficulty: 'beginner',
    estimatedMinutes: 25,
    objectives: [
      'Calculate effective access when combining SMB Share permissions with NTFS permissions.',
      'Explain why the industry standard practice is to grant "Authenticated Users: Change" at the Share level.',
      'Use the Effective Access diagnostic tool in Windows Explorer.'
    ],
    sections: [
      {
        type: 'text',
        heading: 'The Two-Gate Security Model for Network File Access',
        content: 'When a user accesses a file over the network via an SMB share (e.g. \\\\Server01\\Accounting\\Q4.xlsx), Windows forces the request to pass through TWO independent security gates: Gate 1 is Share Permissions, and Gate 2 is NTFS Permissions. The resulting effective permission is ALWAYS the MOST RESTRICTIVE combination of the two!'
      },
      {
        type: 'worked-example',
        heading: 'Effective Access Calculation Scenario',
        steps: [
          {
            title: 'Scenario Setup',
            content: 'User Bob is a member of "Finance".\nShare Permission on \\\\Server01\\Finance: Everyone = Read\nNTFS Permission on C:\\Shares\\Finance: Finance Group = Modify'
          },
          {
            title: 'Evaluation',
            content: 'Over the network: Gate 1 permits "Read". Gate 2 permits "Modify". The most restrictive permission wins -> Bob only has READ access!'
          },
          {
            title: 'Enterprise Best Practice Resolution',
            content: 'Set Share Permissions to "Authenticated Users = Full Control" (or Change), and enforce ALL granular access restrictions exclusively via NTFS. This eliminates contradictory dual-gate maintenance overhead.'
          }
        ]
      }
    ],
    quizId: 'quiz-windows-administration',
    labIds: ['sys-active-directory-lab'],
    prevLessonId: 'sys-win-ntfs-permissions',
    nextLessonId: 'sys-ps-cmdlet-basics'
  },

  // Module 1.3: PowerShell
  {
    id: 'sys-ps-cmdlet-basics',
    courseId: 'windows-administration',
    moduleId: 'sys-mod-win-powershell',
    trackId: 'system',
    slug: 'powershell-cmdlets-object-pipeline',
    title: 'PowerShell Verb-Noun Syntax, Pipeline & Object Streams',
    difficulty: 'beginner',
    estimatedMinutes: 25,
    objectives: [
      'Understand the standardized Verb-Noun naming convention (Get, Set, New, Remove, Test).',
      'Explain why PowerShell passes rich .NET objects down the pipeline rather than raw text.',
      'Use Get-Command and Get-Help to discover cmdlets and parameter specifications.'
    ],
    sections: [
      {
        type: 'text',
        heading: 'Why PowerShell Changed Systems Administration',
        content: 'Legacy shells like Bash and cmd.exe pass unformatted streams of raw text. To extract a process ID in Bash, you must pipe output through grep, awk, and cut. If a column shifts by two spaces, your script breaks. PowerShell revolutionized automation by passing rich, strongly-typed .NET OBJECTS down the pipeline (|). When you pipe Get-Process to another command, you are passing real live objects with properties (Id, ProcessName, WorkingSet64) and methods (Kill(), Start()), requiring zero text parsing!'
      },
      {
        type: 'code',
        language: 'powershell',
        title: 'Discovering and Inspecting Objects',
        content: `# Discover all cmdlets that manipulate network adapters
Get-Command -Noun NetAdapter*

# View all properties and methods available on an object
Get-Process -Name explorer | Get-Member

# Display detailed documentation and examples
Get-Help Get-Service -Examples`
      }
    ],
    quizId: 'quiz-windows-administration',
    labIds: ['sys-powershell-sandbox'],
    prevLessonId: 'sys-win-share-permissions',
    nextLessonId: 'sys-ps-filtering-formatting'
  },
  {
    id: 'sys-ps-filtering-formatting',
    courseId: 'windows-administration',
    moduleId: 'sys-mod-win-powershell',
    trackId: 'system',
    slug: 'powershell-filtering-where-select-format',
    title: 'Where-Object, Select-Object, Sort-Object & Formatting',
    difficulty: 'beginner',
    estimatedMinutes: 25,
    objectives: [
      'Filter object collections using Where-Object with logical operators (-eq, -match, -gt).',
      'Select, calculate, and rename properties using Select-Object.',
      'Differentiate Format-Table/Format-List from data pipelines (Format-Right principle).'
    ],
    sections: [
      {
        type: 'text',
        heading: 'Refining and Shaping Pipeline Data',
        content: 'PowerShell provides powerful core utility cmdlets to filter, sort, and transform collections of objects. The golden rule of PowerShell scripting is: Filter-Left, Format-Right! Filter data as early in the pipeline as possible to minimize memory consumption, and only apply Format-* cmdlets at the very end when displaying output to a human screen.'
      },
      {
        type: 'code',
        language: 'powershell',
        title: 'Filtering and Pipeline Shaping Examples',
        content: `# Find all stopped services set to Automatic startup
Get-Service | Where-Object { $_.StartType -eq 'Automatic' -and $_.Status -eq 'Stopped' }

# Sort processes by memory consumption and select top 5
Get-Process | Sort-Object -Property WorkingSet64 -Descending |
    Select-Object -First 5 -Property ProcessName, Id, @{Name='MemoryMB'; Expression={[math]::Round($_.WorkingSet64 / 1MB, 2)}}`
      }
    ],
    quizId: 'quiz-windows-administration',
    labIds: ['sys-powershell-sandbox'],
    prevLessonId: 'sys-ps-cmdlet-basics',
    nextLessonId: 'sys-ps-system-diagnostics'
  },
  {
    id: 'sys-ps-system-diagnostics',
    courseId: 'windows-administration',
    moduleId: 'sys-mod-win-powershell',
    trackId: 'system',
    slug: 'powershell-system-diagnostics-cim',
    title: 'Querying Hardware, Sockets & Performance via WMI/CIM',
    difficulty: 'beginner',
    estimatedMinutes: 25,
    objectives: [
      'Query hardware and OS configuration using modern Common Information Model (Get-CimInstance).',
      'Test network port accessibility with Test-NetConnection.',
      'Export inventory audits to CSV and JSON formats.'
    ],
    sections: [
      {
        type: 'text',
        heading: 'Enterprise System Inventory with CIM',
        content: 'Modern Windows systems use the Common Information Model (CIM), which supersedes legacy WMI by operating over standards-compliant WS-Management (WinRM) rather than legacy DCOM. With Get-CimInstance, administrators can query BIOS serial numbers, physical RAM sticks, disk drive health, and CPU models instantly across thousands of remote machines.'
      },
      {
        type: 'code',
        language: 'powershell',
        title: 'CIM System Diagnostics Script',
        content: `# Query physical system inventory
Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object Manufacturer, Model, TotalPhysicalMemory
Get-CimInstance -ClassName Win32_BIOS | Select-Object SerialNumber, SMBIOSBIOSVersion

# Test remote TCP port reachability
Test-NetConnection -ComputerName "dc01.corp.test" -Port 389 -InformationLevel Detailed`
      }
    ],
    quizId: 'quiz-windows-administration',
    labIds: ['sys-powershell-sandbox'],
    prevLessonId: 'sys-ps-filtering-formatting',
    nextLessonId: 'sys-ad-forest-domain'
  },

  // --- Course 2: Windows Server and Active Directory ---
  // Module 2.1: AD DS Core
  {
    id: 'sys-ad-forest-domain',
    courseId: 'windows-server',
    moduleId: 'sys-mod-ad-core',
    trackId: 'system',
    slug: 'ad-forests-domains-trusts',
    title: 'Active Directory Architecture: Domains, Forests & Trusts',
    difficulty: 'intermediate',
    estimatedMinutes: 25,
    objectives: [
      'Describe the hierarchical structure: Forests, Trees, Domains, and Domain Controllers.',
      'Explain the role of the Active Directory Schema and Global Catalog (GC).',
      'Differentiate Forest Trusts, External Trusts, and Shortcut Trusts.'
    ],
    sections: [
      {
        type: 'text',
        heading: 'Enterprise Identity and Access Management',
        content: 'Active Directory Domain Services (AD DS) is the central identity store for more than 90% of global enterprises. The top-level security boundary is the FOREST. A forest shares a single common logical Schema (the definition of all object classes and attributes, like user, computer, and email) and a single Global Catalog. Inside a forest, one or more DOMAINS represent administrative and replication boundaries sharing a contiguous DNS namespace.'
      },
      {
        type: 'callout',
        tone: 'tip',
        title: 'Security Boundary Reality',
        content: 'In Active Directory, the DOMAIN is an administrative boundary, but the FOREST is the true ultimate security boundary. A compromised Enterprise Admin in the forest root domain controls every domain controller in the entire forest.'
      }
    ],
    quizId: 'quiz-windows-server',
    labIds: ['sys-active-directory-lab'],
    prevLessonId: 'sys-ps-system-diagnostics',
    nextLessonId: 'sys-ad-ou-hierarchy'
  },
  {
    id: 'sys-ad-ou-hierarchy',
    courseId: 'windows-server',
    moduleId: 'sys-mod-ad-core',
    trackId: 'system',
    slug: 'ad-ou-hierarchy-delegation',
    title: 'Organizational Units (OU), Delegation & Object Lifecycle',
    difficulty: 'intermediate',
    estimatedMinutes: 25,
    objectives: [
      'Design clean, scalable OU hierarchies based on administrative roles or geography.',
      'Explain why default containers (CN=Users, CN=Computers) cannot have GPOs linked.',
      'Delegate specific administrative tasks (e.g. password resets) using the Delegation of Control wizard.'
    ],
    sections: [
      {
        type: 'text',
        heading: 'Organizing Directory Objects for Policy & Delegation',
        content: 'Organizational Units (OUs) are subdivision containers inside an Active Directory domain used to organize users, groups, and computer accounts. Crucially, OUs serve two distinct architectural functions: 1. They act as the smallest unit to which Group Policy Objects (GPOs) can be linked. 2. They serve as boundaries for delegating administrative permissions without granting domain-wide administrator privileges.'
      },
      {
        type: 'worked-example',
        heading: 'Recommended Enterprise OU Structure',
        steps: [
          {
            title: 'Top-Level Production Container: OU=Corp',
            content: 'Contains sub-OUs for logical separation: OU=Workstations, OU=Servers, OU=Users, OU=Tier_Admins, OU=Groups.'
          },
          {
            title: 'Prevent Default Container Placement',
            content: 'Default containers (CN=Users, CN=Computers) are simple CN containers, NOT Organizational Units! Group Policies CANNOT be linked to them. Best practice is to redirect newly domain-joined machines using "redircmp" and "redirusr".'
          }
        ]
      }
    ],
    quizId: 'quiz-windows-server',
    labIds: ['sys-active-directory-lab'],
    prevLessonId: 'sys-ad-forest-domain',
    nextLessonId: 'sys-ad-groups-users'
  },
  {
    id: 'sys-ad-groups-users',
    courseId: 'windows-server',
    moduleId: 'sys-mod-ad-core',
    trackId: 'system',
    slug: 'ad-security-groups-agdlp',
    title: 'Security Groups & the AGDLP Nesting Strategy',
    difficulty: 'intermediate',
    estimatedMinutes: 25,
    objectives: [
      'Compare Group Scopes: Domain Local, Global, and Universal.',
      'Implement the industry standard AGDLP group nesting strategy.',
      'Explain the performance impact of Kerberos token bloat caused by excessive group memberships.'
    ],
    sections: [
      {
        type: 'text',
        heading: 'Structuring Group Memberships for Scalable Access Control',
        content: 'Assigning individual user accounts directly to file shares or database permissions causes administrative chaos when employees change roles. Microsoft created the AGDLP role-based access control methodology to establish predictable, clean group nesting across domains.'
      },
      {
        type: 'table',
        heading: 'The AGDLP Methodology Explained',
        headers: ['Letter', 'Stage Name', 'Purpose & Scope', 'Example'],
        rows: [
          ['A', 'Accounts', 'Individual user or service accounts', 'User: Sarah Jenkins (sjenkins)'],
          ['G', 'Global Group', 'Aggregates accounts sharing a common job function or role', 'Group: G_Accounting_Staff'],
          ['DL', 'Domain Local Group', 'Represents a specific access permission on a specific resource', 'Group: DL_Share_Accounting_Modify'],
          ['P', 'Permissions', 'Actual NTFS or Share permission assigned to the Domain Local group', 'NTFS "Modify" granted to DL_Share_Accounting_Modify']
        ]
      }
    ],
    quizId: 'quiz-windows-server',
    labIds: ['sys-active-directory-lab'],
    prevLessonId: 'sys-ad-ou-hierarchy',
    nextLessonId: 'sys-gpo-processing-order'
  },

  // Module 2.2: Group Policy & Authentication
  {
    id: 'sys-gpo-processing-order',
    courseId: 'windows-server',
    moduleId: 'sys-mod-ad-gpo',
    trackId: 'system',
    slug: 'group-policy-lsdou-precedence',
    title: 'Group Policy Architecture & LSDOU Precedence Rules',
    difficulty: 'intermediate',
    estimatedMinutes: 30,
    objectives: [
      'Memorize and apply the LSDOU Group Policy processing order.',
      'Explain how child OU policies overwrite parent domain policies by default.',
      'Describe the impact of Block Inheritance and Enforce (No Override) settings.'
    ],
    sections: [
      {
        type: 'text',
        heading: 'Centralized Configuration at Enterprise Scale',
        content: 'Group Policy allows administrators to define computer and user configurations centrally in Active Directory and deploy them automatically to thousands of systems. Group Policy Objects (GPOs) are processed sequentially in a strict four-phase order known as LSDOU: Local, Site, Domain, and Organizational Unit.'
      },
      {
        type: 'worked-example',
        heading: 'The LSDOU Evaluation Precedence',
        steps: [
          {
            title: '1. Local Policy',
            content: 'Evaluates the local policy configured on the local workstation (C:\\Windows\\System32\\GroupPolicy).'
          },
          {
            title: '2. Site Policy',
            content: 'Evaluates GPOs linked to the Active Directory physical Site object.'
          },
          {
            title: '3. Domain Policy',
            content: 'Evaluates GPOs linked to the root of the Domain (e.g. Default Domain Policy).'
          },
          {
            title: '4. OU Policy (Parent -> Child)',
            content: 'Evaluates GPOs linked to the user or computer\'s parent OU, and finally child OUs. The LAST policy processed wins!'
          }
        ]
      },
      {
        type: 'callout',
        tone: 'warning',
        title: 'Enforced (No Override) Trump Card',
        content: 'If an executive sets a higher-level GPO (e.g. Domain Policy) to "Enforced", it reverses standard precedence! An Enforced GPO CANNOT be overwritten by child OUs, and ignores "Block Inheritance" completely.'
      }
    ],
    quizId: 'quiz-windows-server',
    labIds: ['sys-active-directory-lab'],
    prevLessonId: 'sys-ad-groups-users',
    nextLessonId: 'sys-kerberos-ntlm'
  },
  {
    id: 'sys-kerberos-ntlm',
    courseId: 'windows-server',
    moduleId: 'sys-mod-ad-gpo',
    trackId: 'system',
    slug: 'kerberos-v5-vs-ntlm-authentication',
    title: 'Authentication Protocols: Kerberos V5 Tickets vs NTLMv2',
    difficulty: 'intermediate',
    estimatedMinutes: 25,
    objectives: [
      'Trace the Kerberos V5 authentication exchange: AS-REQ, AS-REP (TGT), TGS-REQ, TGS-REP.',
      'Explain the purpose of Service Principal Names (SPNs) and KDC (Key Distribution Center).',
      'Identify the security vulnerabilities of legacy NTLM (Pass-the-Hash).'
    ],
    sections: [
      {
        type: 'text',
        heading: 'The Security Backbone of Active Directory',
        content: 'When a user logs into a domain workstation and accesses resources across the network, Active Directory uses Kerberos V5 (RFC 4120). Kerberos relies on trusted symmetric-key cryptography mediated by the Key Distribution Center (KDC) running on domain controllers. Unlike legacy NTLM which transmits challenge-response password hashes across the wire, Kerberos never sends passwords or password hashes to application servers.'
      },
      {
        type: 'worked-example',
        heading: 'The 3-Phase Kerberos Ticket Exchange',
        steps: [
          {
            title: '1. Authentication Service (AS) Exchange',
            content: 'Client sends timestamp encrypted with password hash (AS-REQ). KDC validates and returns a Ticket Granting Ticket (TGT) encrypted with krbtgt key.'
          },
          {
            title: '2. Ticket Granting Service (TGS) Exchange',
            content: 'When client needs to access \\\\Server01\\Share, it presents its TGT to the KDC (TGS-REQ). KDC verifies TGT and issues a Service Ticket for Server01.'
          },
          {
            title: '3. Client / Server (AP) Exchange',
            content: 'Client presents the Service Ticket directly to Server01 (AP-REQ). Server01 decrypts the ticket using its own computer account password and grants access.'
          }
        ]
      }
    ],
    quizId: 'quiz-windows-server',
    labIds: ['sys-active-directory-lab'],
    prevLessonId: 'sys-gpo-processing-order',
    nextLessonId: 'sys-gpo-troubleshooting'
  },
  {
    id: 'sys-gpo-troubleshooting',
    courseId: 'windows-server',
    moduleId: 'sys-mod-ad-gpo',
    trackId: 'system',
    slug: 'gpo-troubleshooting-gpupdate-gpresult',
    title: 'GPO Diagnostics: gpupdate, gpresult, RSOP & Replication',
    difficulty: 'intermediate',
    estimatedMinutes: 25,
    objectives: [
      'Force immediate Group Policy refresh using gpupdate /force.',
      'Generate Resultant Set of Policy (RSoP) reports using gpresult /h.',
      'Troubleshoot SYSVOL replication delays across domain controllers using dfsrdiag.'
    ],
    sections: [
      {
        type: 'text',
        heading: 'Why Policies Fail to Apply',
        content: 'When a user reports that a required desktop setting or security policy did not apply, junior admins often waste time editing the policy repeatedly. Common real-world causes include: The computer is in the wrong OU, WMI filtering blocked the policy, Security Filtering lacked Read permissions for Domain Computers, or SYSVOL replication between domain controllers is out of sync.'
      },
      {
        type: 'code',
        language: 'powershell',
        title: 'Command-Line Group Policy Diagnostics',
        content: `# Force an immediate policy refresh
gpupdate /force

# Generate a comprehensive HTML report of winning GPOs
gpresult /h C:\\Temp\\gpresult_report.html

# Display summary in command window including user/computer security groups
gpresult /r

# Verify replication across Domain Controllers
repadmin /replsummary`
      }
    ],
    quizId: 'quiz-windows-server',
    labIds: ['sys-active-directory-lab'],
    prevLessonId: 'sys-kerberos-ntlm',
    nextLessonId: 'sys-ad-integrated-dns'
  },

  // Module 2.3: Core Enterprise Infrastructure
  {
    id: 'sys-ad-integrated-dns',
    courseId: 'windows-server',
    moduleId: 'sys-mod-win-services',
    trackId: 'system',
    slug: 'ad-integrated-dns-srv-records',
    title: 'Active Directory-Integrated DNS & SRV Record Health',
    difficulty: 'intermediate',
    estimatedMinutes: 25,
    objectives: [
      'Explain how AD-Integrated DNS zones store records directly in the Active Directory database.',
      'Describe multi-master DNS replication and secure dynamic updates.',
      'Verify critical Domain Controller SRV locator records (_ldap._tcp.dc._msdcs).'
    ],
    sections: [
      {
        type: 'text',
        heading: 'The Identity Directory Depends on DNS',
        content: 'Active Directory cannot function without DNS. When you convert a standard DNS zone into an Active Directory-Integrated Zone, DNS records are no longer stored in flat text files on a single primary server. Instead, DNS records become Active Directory database objects replicated multi-master across all domain controllers.'
      },
      {
        type: 'callout',
        tone: 'warning',
        title: 'Netlogon & SRV Records',
        content: 'When a domain controller boots, its Netlogon service registers dozens of Service (SRV) records under the _msdcs.<domain> zone. If a client cannot resolve "_ldap._tcp.dc._msdcs.corp.test", the workstation reports "There are currently no logon servers available to service the logon request"!'
      }
    ],
    quizId: 'quiz-windows-server',
    labIds: ['sys-dns-dhcp-lab'],
    prevLessonId: 'sys-gpo-troubleshooting',
    nextLessonId: 'sys-win-dhcp-failover'
  },
  {
    id: 'sys-win-dhcp-failover',
    courseId: 'windows-server',
    moduleId: 'sys-mod-win-services',
    trackId: 'system',
    slug: 'windows-dhcp-server-failover',
    title: 'Windows DHCP Server: Scopes, Options & Failover Pairs',
    difficulty: 'intermediate',
    estimatedMinutes: 25,
    objectives: [
      'Configure enterprise DHCP scopes, exclusions, and reservations.',
      'Configure essential DHCP Options: 003 Router, 006 DNS Servers, 015 Domain Name.',
      'Deploy DHCP Failover in Load-Sharing (50/50) or Hot-Standby mode.'
    ],
    sections: [
      {
        type: 'text',
        heading: 'High Availability Dynamic Addressing',
        content: 'In legacy Windows Server, providing redundant DHCP required complex 80/20 scope splits or expensive clustering. Windows Server introduced native DHCP Failover (RFC 3074), allowing two DHCP servers to replicate lease databases continuously over TCP port 647.'
      },
      {
        type: 'table',
        heading: 'DHCP Failover Modes Comparison',
        headers: ['Mode', 'Behavior', 'Best Used For'],
        rows: [
          ['Load-Sharing (Active-Active)', 'Both servers actively lease addresses simultaneously (default 50/50 split)', 'Single large campus where both servers are in the same data center'],
          ['Hot-Standby (Active-Passive)', 'Primary server leases all addresses; Secondary server takes over if Primary fails', 'Hub-and-spoke multi-site enterprise with a central disaster recovery backup']
        ]
      }
    ],
    quizId: 'quiz-windows-server',
    labIds: ['sys-dns-dhcp-lab'],
    prevLessonId: 'sys-ad-integrated-dns',
    nextLessonId: 'sys-fsrm-storage-pool'
  },
  {
    id: 'sys-fsrm-storage-pool',
    courseId: 'windows-server',
    moduleId: 'sys-mod-win-services',
    trackId: 'system',
    slug: 'fsrm-file-screening-quotas',
    title: 'File Server Resource Manager (FSRM), Quotas & BitLocker',
    difficulty: 'intermediate',
    estimatedMinutes: 25,
    objectives: [
      'Configure hard and soft directory quotas using File Server Resource Manager (FSRM).',
      'Implement proactive file screening to block ransomware extensions (.locky, .encrypted).',
      'Deploy BitLocker Drive Encryption with Active Directory recovery key backup.'
    ],
    sections: [
      {
        type: 'text',
        heading: 'Storage Governance and Ransomware Defense',
        content: 'File Server Resource Manager (FSRM) is a Windows Server role service providing advanced file management tools. FSRM provides hard quotas (rejecting writes when a limit is reached) and soft quotas (alerting admins while allowing writes). Furthermore, File Screening can monitor shared folders in real time, executing automated scripts and alerting administrators the moment an unauthorized file extension is written.'
      },
      {
        type: 'code',
        language: 'powershell',
        title: 'Configuring FSRM File Screening via PowerShell',
        content: `# Create a file screen group blocking known ransomware patterns
New-FsrmFileGroup -Name "Ransomware_Extensions" -IncludePattern @("*.crypt", "*.locked", "*.ransom")

# Apply active file screen to user home shares
New-FsrmFileScreen -Path "C:\\Shares\\UserProfiles" -FileGroup "Ransomware_Extensions" -Active`
      }
    ],
    quizId: 'quiz-windows-server',
    labIds: ['sys-active-directory-lab'],
    prevLessonId: 'sys-win-dhcp-failover',
    nextLessonId: 'sys-linux-fhs-navigation'
  },

  // --- Course 3: Linux Administration ---
  // Module 3.1: Linux Core
  {
    id: 'sys-linux-fhs-navigation',
    courseId: 'linux-administration',
    moduleId: 'sys-mod-linux-core',
    trackId: 'system',
    slug: 'linux-filesystem-hierarchy-standard',
    title: 'Filesystem Hierarchy Standard (FHS) & Path Navigation',
    difficulty: 'intermediate',
    estimatedMinutes: 20,
    objectives: [
      'Navigate the Linux unified single-tree filesystem rooted at /.',
      'Explain the purpose of key FHS directories: /etc, /var/log, /home, /bin, /dev, /proc, /sys.',
      'Differentiate absolute paths from relative paths.'
    ],
    sections: [
      {
        type: 'text',
        heading: 'The Inverted Tree Architecture',
        content: 'Unlike Windows which mounts storage under independent drive letters (C:\\, D:\\, E:\\), Linux mounts all storage, partitions, optical media, and network volumes into a single unified directory tree starting from the ROOT directory (/).'
      },
      {
        type: 'table',
        heading: 'Essential Linux FHS Directories',
        headers: ['Directory', 'Description', 'Administrator Significance'],
        rows: [
          ['/etc', 'System-wide configuration files', 'Houses configuration files: /etc/ssh/sshd_config, /etc/fstab, /etc/passwd'],
          ['/var/log', 'Variable dynamic logs', 'Houses operational logs: /var/log/syslog, /var/log/auth.log, /var/log/nginx/'],
          ['/proc', 'Virtual pseudo-filesystem representing running kernel', 'Direct kernel introspection: /proc/cpuinfo, /proc/meminfo, /proc/net/'],
          ['/dev', 'Device nodes', 'Hardware abstractions: /dev/sda (hard drive), /dev/null, /dev/urandom'],
          ['/bin & /sbin', 'Core system binaries', 'Essential executable commands and administrator tools']
        ]
      }
    ],
    quizId: 'quiz-linux-administration',
    labIds: ['sys-linux-sandbox'],
    prevLessonId: 'sys-fsrm-storage-pool',
    nextLessonId: 'sys-linux-users-permissions'
  },
  {
    id: 'sys-linux-users-permissions',
    courseId: 'linux-administration',
    moduleId: 'sys-mod-linux-core',
    trackId: 'system',
    slug: 'linux-permissions-chmod-chown-sudo',
    title: 'chmod (Octal & Symbolic), chown, Users & sudoers',
    difficulty: 'intermediate',
    estimatedMinutes: 25,
    objectives: [
      'Calculate octal permission triplets (e.g. 755, 644, 700) using r=4, w=2, x=1.',
      'Modify file ownership using chown and group ownership with chgrp.',
      'Configure granular administrative privileges in /etc/sudoers with visudo.'
    ],
    sections: [
      {
        type: 'text',
        heading: 'POSIX File Permissions',
        content: 'Every file and directory in Linux is owned by a User (u) and a Group (g). Permissions specify what rights are granted to the Owner, the Group, and Others (o). A standard long listing (ls -l) displays a 10-character string like "-rwxr-xr--". Character 1 is the file type (- for regular file, d for directory). Characters 2-4 represent Owner rights, 5-7 represent Group rights, and 8-10 represent Others.'
      },
      {
        type: 'worked-example',
        heading: 'Octal Math Breakdown',
        steps: [
          {
            title: 'Permission Weights',
            content: 'Read (r) = 4 | Write (w) = 2 | Execute (x) = 1 | None (-) = 0'
          },
          {
            title: 'Calculating 755 (rwxr-xr-x)',
            content: 'Owner: r+w+x = 4+2+1 = 7\nGroup: r+-+x = 4+0+1 = 5\nOthers: r+-+x = 4+0+1 = 5\nTotal = chmod 755 filename'
          },
          {
            title: 'Calculating 644 (rw-r--r-- for configuration files)',
            content: 'Owner: r+w+- = 4+2+0 = 6\nGroup: r+-+- = 4+0+0 = 4\nOthers: r+-+- = 4+0+0 = 4\nTotal = chmod 644 /etc/app.conf'
          }
        ]
      }
    ],
    quizId: 'quiz-linux-administration',
    labIds: ['sys-linux-sandbox'],
    prevLessonId: 'sys-linux-fhs-navigation',
    nextLessonId: 'sys-linux-text-processing'
  },
  {
    id: 'sys-linux-text-processing',
    courseId: 'linux-administration',
    moduleId: 'sys-mod-linux-core',
    trackId: 'system',
    slug: 'linux-pipes-grep-awk-sed',
    title: 'Text Streams & Pipelines: grep, awk, sed & Redirects',
    difficulty: 'intermediate',
    estimatedMinutes: 25,
    objectives: [
      'Filter log files and command output using grep with regular expressions.',
      'Extract specific tabular columns using awk.',
      'Perform search-and-replace text modifications with sed.'
    ],
    sections: [
      {
        type: 'text',
        heading: 'The Unix Philosophy: Small Tools Chained by Pipes',
        content: 'The core philosophy of Unix/Linux is: Write programs that do one thing well, and write programs to work together. By combining stream inputs/outputs with pipes (|) and redirects (> and >>), system administrators can parse megabytes of raw text logs in fractions of a second.'
      },
      {
        type: 'code',
        language: 'bash',
        title: 'Practical Enterprise Pipeline Command Examples',
        content: `# Find all failed SSH login attempts in auth.log
grep "Failed password" /var/log/auth.log

# Extract the offending IP addresses (Column 11) and count unique occurrences
grep "Failed password" /var/log/auth.log | awk '{print $11}' | sort | uniq -c | sort -nr

# Replace server IP in configuration file using sed
sed -i 's/10.0.0.1/10.0.0.2/g' /etc/nginx/sites-available/default`
      }
    ],
    quizId: 'quiz-linux-administration',
    labIds: ['sys-linux-sandbox'],
    prevLessonId: 'sys-linux-users-permissions',
    nextLessonId: 'sys-linux-systemd-units'
  },

  // Module 3.2: Services & Process Management
  {
    id: 'sys-linux-systemd-units',
    courseId: 'linux-administration',
    moduleId: 'sys-mod-linux-services',
    trackId: 'system',
    slug: 'systemd-units-systemctl-journalctl',
    title: 'systemd Architecture: Units, Targets & journalctl Inspection',
    difficulty: 'intermediate',
    estimatedMinutes: 30,
    objectives: [
      'Explain systemd as PID 1 (the initial process) and unit file structure (.service, .target).',
      'Manage daemon lifecycles with systemctl (start, stop, restart, reload, enable, status).',
      'Query structured binary journal logs with journalctl.'
    ],
    sections: [
      {
        type: 'text',
        heading: 'The Modern Linux Init System',
        content: 'systemd is the init system and service manager that bootstraps user space and manages all processes as PID 1 across modern enterprise distributions (RHEL, Ubuntu, Debian, Rocky Linux). systemd utilizes declarative UNIT files to define service dependencies, restart policies, and resource limits.'
      },
      {
        type: 'code',
        language: 'bash',
        title: 'Essential systemctl & journalctl Commands',
        content: `# Check service status and recent log output
systemctl status nginx.service

# Enable service to start automatically on system boot
systemctl enable --now nginx.service

# Tail logs for a specific service in real time
journalctl -u nginx.service -f

# View kernel ring buffer errors since last boot
journalctl -k -p err -b`
      }
    ],
    quizId: 'quiz-linux-administration',
    labIds: ['sys-linux-sandbox'],
    prevLessonId: 'sys-linux-text-processing',
    nextLessonId: 'sys-linux-package-management'
  },
  {
    id: 'sys-linux-package-management',
    courseId: 'linux-administration',
    moduleId: 'sys-mod-linux-services',
    trackId: 'system',
    slug: 'package-management-apt-dnf-rpm',
    title: 'Enterprise Package Management: APT, DNF/RPM & Repositories',
    difficulty: 'intermediate',
    estimatedMinutes: 25,
    objectives: [
      'Compare Debian/Ubuntu package management (apt/dpkg) with RHEL/Fedora (dnf/rpm).',
      'Explain repository cryptographic signatures (GPG keys) and package verification.',
      'Automate unattended security updates.'
    ],
    sections: [
      {
        type: 'text',
        heading: 'Software Lifecycle & Dependency Resolution',
        content: 'Enterprise Linux distributions manage software installation, updates, and removals through automated package managers that resolve complex dependency trees. Debian/Ubuntu systems use the Advanced Package Tool (APT), while Red Hat Enterprise Linux (RHEL) systems use DNF (Dandified YUM).'
      },
      {
        type: 'table',
        heading: 'APT vs DNF Command Rosetta Stone',
        headers: ['Task', 'Debian / Ubuntu (APT)', 'RHEL / Rocky / Fedora (DNF)'],
        rows: [
          ['Update Package Metadata', 'apt update', 'dnf check-update'],
          ['Upgrade Installed Software', 'apt upgrade -y', 'dnf upgrade -y'],
          ['Install Package', 'apt install nginx', 'dnf install nginx'],
          ['Remove Package', 'apt remove nginx', 'dnf remove nginx'],
          ['Search Repositories', 'apt search wireguard', 'dnf search wireguard']
        ]
      }
    ],
    quizId: 'quiz-linux-administration',
    labIds: ['sys-linux-sandbox'],
    prevLessonId: 'sys-linux-systemd-units',
    nextLessonId: 'sys-linux-cron-storage'
  },
  {
    id: 'sys-linux-cron-storage',
    courseId: 'linux-administration',
    moduleId: 'sys-mod-linux-services',
    trackId: 'system',
    slug: 'cron-scheduling-storage-fstab',
    title: 'Scheduled Tasks with cron & Storage (mount, fstab, df, du)',
    difficulty: 'intermediate',
    estimatedMinutes: 25,
    objectives: [
      'Schedule automated maintenance scripts using crontab (minute, hour, day, month, weekday).',
      'Inspect disk capacity and directory consumption using df -h and du -sh.',
      'Configure persistent storage partitions in /etc/fstab with UUIDs.'
    ],
    sections: [
      {
        type: 'text',
        heading: 'Automated Job Execution & Disk Management',
        content: 'The cron daemon executes scheduled shell jobs in the background. Disk management requires monitoring mounted filesystem usage with "df -h" (disk free) and hunting down bloated directories with "du -sh" (disk usage).'
      },
      {
        type: 'code',
        language: 'text',
        title: 'The 5-Field crontab Syntax',
        content: `# .---------------- minute (0 - 59)
# |  .------------- hour (0 - 23)
# |  |  .---------- day of month (1 - 31)
# |  |  |  .------- month (1 - 12)
# |  |  |  |  .---- day of week (0 - 6) (Sunday=0)
# *  *  *  *  * user-name command to be executed
# Run database backup every night at 2:30 AM:
30 2 * * * /opt/scripts/backup-db.sh >> /var/log/backup.log 2>&1`
      }
    ],
    quizId: 'quiz-linux-administration',
    labIds: ['sys-linux-sandbox'],
    prevLessonId: 'sys-linux-package-management',
    nextLessonId: 'sys-linux-ip-routing'
  },

  // Module 3.3: Linux Networking & Security
  {
    id: 'sys-linux-ip-routing',
    courseId: 'linux-administration',
    moduleId: 'sys-mod-linux-networking',
    trackId: 'system',
    slug: 'linux-iproute2-ip-addr-ip-route',
    title: 'Linux Networking: iproute2 (ip addr, ip route) & Resolv.conf',
    difficulty: 'intermediate',
    estimatedMinutes: 25,
    objectives: [
      'Inspect and assign IP addresses using modern ip addr and ip link commands.',
      'Inspect and configure static default gateways using ip route.',
      'Configure DNS resolution via /etc/resolv.conf and systemd-resolved.'
    ],
    sections: [
      {
        type: 'text',
        heading: 'Modern Linux Network Configuration with iproute2',
        content: 'The legacy net-tools package (ifconfig, netstat, route) was deprecated over a decade ago. Modern Linux uses the iproute2 suite, which interfaces directly with the Linux kernel via netlink sockets.'
      },
      {
        type: 'code',
        language: 'bash',
        title: 'Modern iproute2 Command Reference',
        content: `# Display IP addresses and link states for all interfaces
ip addr show

# Bring an interface Up or Down
sudo ip link set dev eth0 up

# Inspect the routing table and default gateway
ip route show

# Add a static route to a remote subnet
sudo ip route add 10.50.0.0/16 via 192.168.1.1 dev eth0`
      }
    ],
    quizId: 'quiz-linux-administration',
    labIds: ['sys-linux-sandbox'],
    prevLessonId: 'sys-linux-cron-storage',
    nextLessonId: 'sys-linux-socket-diagnostics'
  },
  {
    id: 'sys-linux-socket-diagnostics',
    courseId: 'linux-administration',
    moduleId: 'sys-mod-linux-networking',
    trackId: 'system',
    slug: 'linux-socket-triage-ss-lsof',
    title: 'Socket Inspection with ss & Open Files with lsof',
    difficulty: 'intermediate',
    estimatedMinutes: 25,
    objectives: [
      'Query active listening TCP/UDP sockets using ss -tulnp.',
      'Identify the exact Process ID (PID) and daemon holding a network port.',
      'Use lsof to inspect open file handles and network connections.'
    ],
    sections: [
      {
        type: 'text',
        heading: 'Real-Time Network Port Triage',
        content: 'When an application fails to start with "Address already in use (EADDRINUSE)", the administrator must immediately identify which rogue process is occupying that port. The "ss" (socket statistics) utility dumps kernel socket tables instantly.'
      },
      {
        type: 'terminal-output',
        title: 'Inspecting Listening Ports with ss -tulnp',
        content: `$ sudo ss -tulnp
Netid  State   Recv-Q  Send-Q   Local Address:Port   Peer Address:Port  Process
tcp    LISTEN  0       128            0.0.0.0:22          0.0.0.0:*      users:(("sshd",pid=842,fd=3))
tcp    LISTEN  0       511            0.0.0.0:80          0.0.0.0:*      users:(("nginx",pid=1254,fd=6))
tcp    LISTEN  0       128          127.0.0.1:8443        0.0.0.0:*      users:(("node",pid=25952,fd=19))`
      }
    ],
    quizId: 'quiz-linux-administration',
    labIds: ['sys-linux-sandbox'],
    prevLessonId: 'sys-linux-ip-routing',
    nextLessonId: 'sys-linux-ssh-hardening'
  },
  {
    id: 'sys-linux-ssh-hardening',
    courseId: 'linux-administration',
    moduleId: 'sys-mod-linux-networking',
    trackId: 'system',
    slug: 'openssh-hardening-ed25519-keys',
    title: 'OpenSSH Hardening: Ed25519 Keys & Security Bastions',
    difficulty: 'intermediate',
    estimatedMinutes: 30,
    objectives: [
      'Generate modern Ed25519 elliptic-curve SSH key pairs.',
      'Harden /etc/ssh/sshd_config by disabling passwords and root logins.',
      'Deploy and configure fail2ban to mitigate brute-force dictionary attacks.'
    ],
    sections: [
      {
        type: 'text',
        heading: 'Securing the Primary Management Gateway',
        content: 'Secure Shell (SSH / RFC 4253) is the universal protocol for remote Linux administration. Leaving an SSH server exposed to the public Internet with default settings invites continuous brute-force dictionary bot attacks. Hardening OpenSSH requires disabling password authentication entirely and mandating elliptic curve cryptographic keys (Ed25519).'
      },
      {
        type: 'code',
        language: 'bash',
        title: 'Hardened /etc/ssh/sshd_config Snippet',
        content: `# Enforce Ed25519 and modern cryptography
Protocol 2
Port 22

# Disable root login over SSH
PermitRootLogin no

# Enforce Public Key Authentication only
PubkeyAuthentication yes
PasswordAuthentication no
PermitEmptyPasswords no
ChallengeResponseAuthentication no

# Limit authentication attempts
MaxAuthTries 3`
      }
    ],
    quizId: 'quiz-linux-administration',
    labIds: ['sys-linux-sandbox'],
    prevLessonId: 'sys-linux-socket-diagnostics',
    nextLessonId: 'sys-ops-monitoring-metrics'
  },

  // --- Course 4: Enterprise Systems Operations ---
  // Module 4.1: Observability & Patching
  {
    id: 'sys-ops-monitoring-metrics',
    courseId: 'enterprise-operations',
    moduleId: 'sys-mod-ops-observability',
    trackId: 'system',
    slug: 'system-telemetry-metrics-probes',
    title: 'System Telemetry: CPU, Memory, Disk I/O & Synthetic Probes',
    difficulty: 'advanced',
    estimatedMinutes: 25,
    objectives: [
      'Differentiate the Four Golden Signals of Monitoring: Latency, Traffic, Errors, and Saturation.',
      'Differentiate Push-based vs Pull-based telemetry architectures (e.g. Prometheus).',
      'Deploy synthetic transaction probes to detect user-facing service degradation proactively.'
    ],
    sections: [
      {
        type: 'text',
        heading: 'The Four Golden Signals (Google SRE)',
        content: 'System monitoring in enterprise environments should not consist of hundreds of uncoordinated email alerts. Google Site Reliability Engineering (SRE) defines the Four Golden Signals that measure true system health: 1. Latency (time to serve requests), 2. Traffic (demand/QPS), 3. Errors (rate of HTTP 5xx or failures), 4. Saturation (fullness of memory, CPU, or socket pools).'
      },
      {
        type: 'table',
        heading: 'Resource Bottlenecks & Triage Indicators',
        headers: ['Subsystem', 'Key Metric', 'Saturation Indicator', 'Triage Action'],
        rows: [
          ['CPU', 'CPU Utilization % & Load Average', 'Run queue length exceeds CPU core count', 'Profile thread stacks, identify CPU-bound loop'],
          ['Memory', 'Available RAM & Page File Swapping', 'Continuous hard page faults / OOM killer invoked', 'Inspect memory leak in application heap'],
          ['Disk I/O', 'Disk Queue Length & Average Latency', 'IOPS latency spikes > 25ms', 'Analyze random write bottlenecks or rebuild RAID']
        ]
      }
    ],
    quizId: 'quiz-enterprise-operations',
    labIds: ['sys-powershell-sandbox'],
    prevLessonId: 'sys-linux-ssh-hardening',
    nextLessonId: 'sys-ops-log-aggregation'
  },
  {
    id: 'sys-ops-log-aggregation',
    courseId: 'enterprise-operations',
    moduleId: 'sys-mod-ops-observability',
    trackId: 'system',
    slug: 'centralized-logging-siem-audit-trails',
    title: 'Centralized Log Ingestion, SIEM Basics & Audit Trails',
    difficulty: 'advanced',
    estimatedMinutes: 25,
    objectives: [
      'Explain the necessity of centralized logging over per-server log inspection.',
      'Describe the architecture of modern log pipelines: Shippers, Brokers, Indexers, and UI.',
      'Ensure tamper-evident audit trails with cryptographic HMAC hashing.'
    ],
    sections: [
      {
        type: 'text',
        heading: 'Log Aggregation & Security Information Event Management',
        content: 'In a microservice or multi-server enterprise environment with 500 servers, logging into individual machines to check local log files during an outage is impossible. Centralized log aggregation ships logs from all servers into a unified, indexed SIEM database (Elasticsearch, Splunk, Graylog, or EJII HMAC Audit Store), allowing correlation of incidents across distributed services in seconds.'
      },
      {
        type: 'table',
        heading: 'Core Components of an Enterprise Log Pipeline',
        headers: ['Pipeline Stage', 'Function', 'Industry Standard Technologies'],
        rows: [
          ['1. Collection / Shipper', 'Tails local files and forwards over TLS', 'Fluent Bit, Logstash, Vector, Windows Event Forwarding (WEF)'],
          ['2. Ingestion Broker', 'High-throughput message buffer for backpressure', 'Apache Kafka, RabbitMQ, Redis Streams'],
          ['3. Indexer / Storage', 'Tokenizes and indexes log lines for fast search', 'Elasticsearch, OpenSearch, ClickHouse, Grafana Loki'],
          ['4. Visualization & SIEM', 'Dashboarding, alerting, and correlation queries', 'Kibana, Grafana, Splunk Enterprise, Wazuh SIEM']
        ]
      },
      {
        type: 'callout',
        tone: 'tip',
        title: 'Cryptographic Immutability',
        content: 'To prevent malicious attackers or rogue administrators from tampering with security audit logs, enterprise log forwarders compute sequential HMAC-SHA256 hashes linking each log line to the previous one, forming an immutable tamper-evident chain.'
      }
    ],
    quizId: 'quiz-enterprise-operations',
    labIds: ['sys-powershell-sandbox'],
    prevLessonId: 'sys-ops-monitoring-metrics',
    nextLessonId: 'sys-ops-patch-management'
  },
  {
    id: 'sys-ops-patch-management',
    courseId: 'enterprise-operations',
    moduleId: 'sys-mod-ops-observability',
    trackId: 'system',
    slug: 'staged-patch-management-maintenance',
    title: 'Staged Patching Lifecycle, Testing, Rollback & Maintenance',
    difficulty: 'advanced',
    estimatedMinutes: 25,
    objectives: [
      'Design a phased deployment ring architecture: Ring 0 (Canary), Ring 1 (Pilot), Ring 2 (Broad Production).',
      'Establish maintenance windows and clear change advisory board (CAB) approvals.',
      'Formulate and validate automated rollback procedures prior to patch installation.'
    ],
    sections: [
      {
        type: 'text',
        heading: 'Balancing Vulnerability Remediation with Service Stability',
        content: 'Unpatched servers expose enterprises to critical ransomware vulnerabilities (Zero-Day CVEs), yet rushed, untested patches frequently cause blue screens, database corruptions, or broken network drivers. A professional Patch Management Lifecycle uses phased deployment rings to validate patches before broad rollout.'
      },
      {
        type: 'worked-example',
        heading: 'The 3-Phase Enterprise Patching Ring Model',
        steps: [
          {
            title: 'Ring 0: Canary / Lab (Day 1)',
            content: 'Deploy patches to isolated staging virtual machines and development servers. Execute automated regression tests.'
          },
          {
            title: 'Ring 1: Pilot / IT Staff (Day 3-7)',
            content: 'Deploy to IT internal workstations and secondary redundant cluster nodes. Monitor for 72 hours.'
          },
          {
            title: 'Ring 2: General Production (Day 14)',
            content: 'Deploy to all remaining production systems during an approved maintenance window, with verified snapshots available for instant rollback.'
          }
        ]
      }
    ],
    quizId: 'quiz-enterprise-operations',
    labIds: ['sys-powershell-sandbox'],
    prevLessonId: 'sys-ops-log-aggregation',
    nextLessonId: 'sys-ops-backup-321'
  },

  // Module 4.2: Resilience & DR
  {
    id: 'sys-ops-backup-321',
    courseId: 'enterprise-operations',
    moduleId: 'sys-mod-ops-resilience',
    trackId: 'system',
    slug: 'backup-strategies-321-rto-rpo',
    title: 'The 3-2-1 Backup Strategy, RTO, RPO & Snapshot Mechanics',
    difficulty: 'advanced',
    estimatedMinutes: 25,
    objectives: [
      'Define the 3-2-1 backup rule and immutable offline copies.',
      'Differentiate Recovery Time Objective (RTO) from Recovery Point Objective (RPO).',
      'Explain Volume Shadow Copy Service (VSS) and hypervisor storage snapshots.'
    ],
    sections: [
      {
        type: 'text',
        heading: 'The Foundation of Business Continuity',
        content: 'Backups are an enterprise\'s final line of defense against hardware failure, human error, and ransomware extortion. The industry gold standard is the 3-2-1 BACKUP RULE: Maintain at least 3 total copies of critical data, across 2 different storage media types (e.g. disk array and tape or cloud), with at least 1 copy stored completely off-site in an immutable (WORM - Write Once, Read Many) air-gapped repository.'
      },
      {
        type: 'callout',
        tone: 'info',
        title: 'RTO vs RPO Definitions',
        content: '• RPO (Recovery Point Objective): "How much data can we afford to lose?" Measured in time. If backups run every 4 hours, your RPO is 4 hours.\n• RTO (Recovery Time Objective): "How quickly must the system be restored?" Measured in time. If it takes 2 hours to spin up the backup VM, your RTO is 2 hours.'
      }
    ],
    quizId: 'quiz-enterprise-operations',
    labIds: ['sys-powershell-sandbox'],
    prevLessonId: 'sys-ops-patch-management',
    nextLessonId: 'sys-ops-restore-validation'
  },
  {
    id: 'sys-ops-restore-validation',
    courseId: 'enterprise-operations',
    moduleId: 'sys-mod-ops-resilience',
    trackId: 'system',
    slug: 'disaster-recovery-drills-restore-validation',
    title: 'Disaster Recovery Drill Methodology & Sandbox Validation',
    difficulty: 'advanced',
    estimatedMinutes: 25,
    objectives: [
      'Explain the fundamental difference between "Backup" and "Verified Restore".',
      'Execute automated sandbox restore validation drills (SureBackup/Isolated Sandbox).',
      'Measure and document actual RTO performance against SLA commitments.'
    ],
    sections: [
      {
        type: 'text',
        heading: 'An Untested Backup Does Not Exist',
        content: 'The most dangerous assumption a systems engineer can make is that a backup job with a green checkmark means the system can be restored. Backup images can suffer silent database corruptions, missing encryption keys, or unbootable driver states. True resilience requires scheduled, automated RESTORE VALIDATION DRILLS where backup images are booted in an isolated network sandbox and tested with automated synthetic application scripts.'
      },
      {
        type: 'table',
        heading: 'Automated Restore Validation Checklist',
        headers: ['Validation Phase', 'Inspection Action', 'Pass Criteria'],
        rows: [
          ['1. Sandbox Network Isolation', 'Boot VM in non-routed virtual switch (vSwitch)', 'Zero packets leak to production subnet'],
          ['2. Operating System Heartbeat', 'Check hypervisor guest integration tools', 'OS reaches login prompt in under 3 minutes'],
          ['3. Service Readiness Probe', 'HTTP GET or TCP port socket check', 'Application daemon returns HTTP 200 OK'],
          ['4. Database Integrity Check', 'Execute DBCC CHECKDB or pg_dump verification', 'Zero allocation or consistency errors']
        ]
      },
      {
        type: 'callout',
        tone: 'warning',
        title: 'Air-Gapping Against Ransomware',
        content: 'Ensure backup targets utilize object lock / S3-compatible immutability or physical air-gaps. If compromised admin credentials can issue a deletion command against your backup repository, your disaster recovery plan is incomplete.'
      }
    ],
    quizId: 'quiz-enterprise-operations',
    labIds: ['sys-powershell-sandbox'],
    prevLessonId: 'sys-ops-backup-321',
    nextLessonId: 'sys-ops-ha-failover'
  },
  {
    id: 'sys-ops-ha-failover',
    courseId: 'enterprise-operations',
    moduleId: 'sys-mod-ops-resilience',
    trackId: 'system',
    slug: 'high-availability-clustering-failover',
    title: 'High Availability Concepts: Active-Passive, Clustering & VIPs',
    difficulty: 'advanced',
    estimatedMinutes: 25,
    objectives: [
      'Compare Active-Passive failover clustering with Active-Active load balancing.',
      'Explain Virtual IP addresses (VIP) and heartbeats (VRRP, CARP, Keepalived).',
      'Mitigate split-brain scenarios using witness disks, cloud witnesses, and quorum.'
    ],
    sections: [
      {
        type: 'text',
        heading: 'Eliminating Single Points of Failure (SPOF)',
        content: 'High Availability (HA) designs ensure that the failure of any single physical server, power supply, or network link does not disrupt end-user operations. Cluster nodes monitor each other via heartbeat networks. If the active node stops responding, the standby node acquires the Virtual IP (VIP) address and assumes service leadership.'
      },
      {
        type: 'callout',
        tone: 'warning',
        title: 'The Split-Brain Nightmare',
        content: 'If the heartbeat link between two cluster nodes is severed while both nodes are healthy, both nodes may believe the other is dead and attempt to write to shared storage simultaneously! This "split-brain" condition destroys file systems. QUORUM (majority voting using a witness server or disk) prevents split-brain by requiring 50% + 1 votes to assume cluster ownership.'
      }
    ],
    quizId: 'quiz-enterprise-operations',
    labIds: ['sys-powershell-sandbox'],
    prevLessonId: 'sys-ops-restore-validation',
    nextLessonId: 'sys-ops-incident-lifecycle'
  },

  // Module 4.3: Incident Management
  {
    id: 'sys-ops-incident-lifecycle',
    courseId: 'enterprise-operations',
    moduleId: 'sys-mod-ops-incident',
    trackId: 'system',
    slug: 'itil-incident-management-lifecycle',
    title: 'ITIL Incident Management, Severity Levels & Escalation',
    difficulty: 'advanced',
    estimatedMinutes: 25,
    objectives: [
      'Categorize incidents by Urgency and Impact into Severity Levels (Sev-1 to Sev-4).',
      'Explain the role of the Incident Commander during major outages.',
      'Establish technical war rooms and execute clear operational communication.'
    ],
    sections: [
      {
        type: 'text',
        heading: 'Orchestrating Order During Crisis',
        content: 'When a critical production service crashes, panic and uncoordinated modifications by multiple engineers will compound the outage. ITIL Incident Management establishes a structured workflow: Detection -> Classification -> Investigation -> Containment -> Recovery -> Closure.'
      },
      {
        type: 'table',
        heading: 'Enterprise Severity Classification Matrix',
        headers: ['Severity', 'Impact Description', 'Target Response SLA', 'Governance Protocol'],
        rows: [
          ['Sev-1 (Critical)', 'Core revenue-generating or clinical service completely down; no workaround', '< 15 Minutes', 'Emergency War Room, Incident Commander assigned, executive hourly briefings'],
          ['Sev-2 (Major)', 'Significant service degradation affecting an entire department or branch', '< 1 Hour', 'Senior engineering escalation, priority triage'],
          ['Sev-3 (Moderate)', 'Non-critical system issue; acceptable workaround available', '< 8 Hours', 'Standard queue assignment during business hours'],
          ['Sev-4 (Low)', 'Minor cosmetic issue or general inquiry with negligible business impact', '< 48 Hours', 'Standard backlog processing']
        ]
      }
    ],
    quizId: 'quiz-enterprise-operations',
    labIds: ['sys-dns-dhcp-lab'],
    prevLessonId: 'sys-ops-ha-failover',
    nextLessonId: 'sys-ops-troubleshooting-methodology'
  },
  {
    id: 'sys-ops-troubleshooting-methodology',
    courseId: 'enterprise-operations',
    moduleId: 'sys-mod-ops-incident',
    trackId: 'system',
    slug: 'divide-and-conquer-troubleshooting',
    title: 'Divide-and-Conquer Systems Troubleshooting Methodology',
    difficulty: 'advanced',
    estimatedMinutes: 25,
    objectives: [
      'Apply hypothesis-driven troubleshooting to complex multi-tier failures.',
      'Verify the "What Changed?" factor: recent deployments, configuration changes, or certificate expirations.',
      'Isolate failure domains across client, network, load balancer, app server, and database.'
    ],
    sections: [
      {
        type: 'text',
        heading: 'The Scientific Method for Systems Operations',
        content: 'Troubleshooting is not random trial-and-error; it is the systematic application of the scientific method: 1. Gather observable symptoms, 2. Formulate testable hypotheses, 3. Execute controlled diagnostic tests that isolate variables, 4. Implement verified remediations, 5. Validate full recovery.'
      },
      {
        type: 'callout',
        tone: 'tip',
        title: 'The Number One Question: "What Changed?"',
        content: 'Over 80% of enterprise outages are caused by recent changes (new code deployments, DNS record edits, firewall rule pushes, or expired TLS certificates). Before assuming hardware failure, always check the change log for what was modified in the last 24 hours!'
      }
    ],
    quizId: 'quiz-enterprise-operations',
    labIds: ['sys-dns-dhcp-lab'],
    prevLessonId: 'sys-ops-incident-lifecycle',
    nextLessonId: 'sys-ops-runbook-documentation'
  },
  {
    id: 'sys-ops-runbook-documentation',
    courseId: 'enterprise-operations',
    moduleId: 'sys-mod-ops-incident',
    trackId: 'system',
    slug: 'blameless-post-mortems-runbooks',
    title: 'Creating Blameless Post-Mortems & Operational Runbooks',
    difficulty: 'advanced',
    estimatedMinutes: 30,
    objectives: [
      'Write actionable, step-by-step Standard Operating Procedures (SOPs) and runbooks.',
      'Conduct blameless post-mortem reviews focused on systemic improvements.',
      'Track corrective action items (CAPA) to completion to prevent incident recurrence.'
    ],
    sections: [
      {
        type: 'text',
        heading: 'Transforming Outages into Institutional Resilience',
        content: 'High-performing engineering teams embrace the principle of BLAMELESS POST-MORTEMS. If an engineer makes a typo that crashes a server, the root cause is not "human error"—the root cause is that the system lacked automated validation guards, canary deployment stages, and peer review checks. A culture of blame encourages engineers to hide mistakes; a blameless culture encourages transparent reporting and continuous system hardening.'
      },
      {
        type: 'table',
        heading: 'Structure of a Production Incident Post-Mortem',
        headers: ['Section', 'Required Details'],
        rows: [
          ['Executive Summary', 'High-level description of what occurred, duration, and business impact.'],
          ['Timeline (UTC)', 'Timestamped sequence of detection, alerts, actions taken, and recovery.'],
          ['Root Cause Analysis', 'The fundamental technical and architectural contributing factors (5 Whys).'],
          ['Trigger Event', 'The specific action or failure that initiated the sequence.'],
          ['Action Items (Jira/Tickets)', 'Specific preventative engineering tasks with assignees and target completion dates.']
        ]
      }
    ],
    quizId: 'quiz-enterprise-operations',
    labIds: ['sys-dns-dhcp-lab'],
    prevLessonId: 'sys-ops-troubleshooting-methodology',
    nextLessonId: null
  }
];

module.exports = {
  SYSTEM_COURSES,
  SYSTEM_MODULES,
  SYSTEM_LESSONS
};
