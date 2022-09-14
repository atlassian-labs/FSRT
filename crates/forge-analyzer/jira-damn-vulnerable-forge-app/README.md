# Damn Vulnerable Forge App (Jira edition)

> ## WARNING!
> Please don't install this app into any production sites, as it is *extremely* vulnerable. You have been warned.

## Introduction

Damn Vulnerable Forge App is an intentionally vulnerable [Forge](https://developer.atlassian.com/platform/forge) application, that was created
to teach people how to exploit common Forge app vulnerabilities. Furthermore, it can be an example for Forge app developers on how *not* to
create a Forge app.

In this scenario, you will play as an unprivileged Jira user who *shouldn't* have access to several flags scattered around the Jira instance.
Fortunately, the admin of the site decided to install an app of questionable security, which may help you in your quest.

## Accessing DVFA

1. Sign into an account at [damn-vulnerable-forge-app](https://damn-vulnerable-forge-app.atlassian.net)
1. Find flags

### TODO

- Create writeups for the three exercises
- Create a flag submission microservice(like CTFd)
- XSS challenge/validator
- Crypto challenge involving random numbers generated in the snapshot context

### Notes

- There are three flags at the moment.
