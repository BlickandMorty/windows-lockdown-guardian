# Operational Warning

This project changes the Windows hosts file, managed-browser registry policy, application restrictions, NTFS permissions, and Task Scheduler.

Before applying:

- Make a system restore point and a tested backup.
- Confirm you have a second device for documentation and emergency school/work access.
- Review the exact domain and executable lists.
- Treat `adultDomains` as a local fallback list, not comprehensive category filtering. Broad adult-content coverage requires an upstream DNS/category provider configured by the account owner.
- Keep the policy narrow; do not add broad or ambiguous domains.
- Understand that `Permanent` mode intentionally ships without a normal removal workflow.
- Test school, Microsoft, finance, accessibility, gaming, developer, and Qobuz workflows after installation.

Do not apply this to a work-managed, school-managed, shared, or life-critical computer without the administrator/owner's approval.
