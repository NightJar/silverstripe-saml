# Troubleshooting

This guide contains a list of solutions to problems we have encountered in practice when integrating this module. This is not an exhaustive list, but it may provide assistance in case of some common issues.

**Note:** For LDAP troubleshooting, please see [the LDAP documentation](https://github.com/silverstripe/silverstripe-ldap/blob/master/docs/en/troubleshooting.md).

## Table of contents

<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->

- ["Invalid issuer" error in Silverstripe](#invalid-issuer-error-in-silverstripe)
- [Updating ADFS from 1.0 to 2.0](#updating-adfs-from-10-to-20)
- [ADFS 3.0 and Chrome authentication](#adfs-30-and-chrome-authentication)
- [Intranet level security settings](#intranet-level-security-settings)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

## "Invalid issuer" error in Silverstripe

In your SAML configuration file for Silverstripe, `entityId` must match *exactly* to the correct URL (including the protocol).

The correct URL can be extracted from ADFS by checking the "Federation Service Properties".

## Updating ADFS from 1.0 to 2.0

To be able to use the SAML Single Sign On functionality you need to have ADFS 2.0 or greater.
In some cases ADFS 1.0 is installed, but you can upgrade for free with [an update from Microsoft](http://www.microsoft.com/en-us/download/details.aspx?id=10909).

[Installing Active Directory Federation Services (ADFS) 2.0](http://pipe2text.com/?page_id=285) information is available.

## ADFS 3.0 and Chrome authentication

ADFS 3.0, such as the kind found on Windows Server 2012 requires some extra configuration for Chrome to authenticate.

Run these commands on the ADFS server using Powershell:

	Set-ADFSProperties –ExtendedProtectionTokenCheck None
	Set-ADFSProperties -WIASupportedUserAgents @("MSIE 6.0", "MSIE 7.0", "MSIE 8.0", "MSIE 9.0", "MSIE 10.0", "Trident/7.0", "MSIPC", "Windows Rights Management Client", "Mozilla/5.0")

You will then need to restart the Active Directory service in Windows.

## Intranet level security settings

Internet Explorer running on your Windows machine must have the ADFS URL, e.g. https://adfs.mydomain.com set with "intranet" security settings, otherwise the browser will not attempt Windows authentication with the ADFS server, as the default is "internet" security settings.

More [detailed information](https://sysadminspot.com/windows/google-chrome-and-ntlm-auto-logon-using-windows-authentication/) can be found on this subject.
