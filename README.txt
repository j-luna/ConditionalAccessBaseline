This script deploys base conditional access policy templates.

REQUIREMENTS:

-- Requires PowerShell 7 (PowerShell Core) - https://github.com/PowerShell/PowerShell
-- Requires Microsoft.Graph.Authentication module (installs if not present).

TO RUN:

-- Simply run the "Deploy-CATemplates.ps1" script in PowerShell 7.
-- When prompted, sign into the target M365 tenant as a global admin
-- Do not modify or change the locations of files in the accompanying folders.


FEATURES:

1. MFA for standard users, administrators, and service accounts ("Trusted Locations Only")
2. Creates a geolocation policy that blocks sign-in outside of the United States
3. Creates a custom authentication strength called "Baseline Auth Strength" that allows the
   following combinations:

   Windows Hello For Business
   Passkeys (FIDO2)
   Certificate-based Authentication (Multifactor)
   Password + Microsoft Authenticator (Push Notification)
   Password + Software OATH token
   Password + Hardware OATH token

4. Creates the "United States" named location for use in the geolocation policy
5. Creates a Trusted Locations Only and a Geolocation Exclusions group
6. Places all policies in "Report Only" mode after creation