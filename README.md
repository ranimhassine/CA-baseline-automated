# CA-baseline-automated

This repository provides a set of **Microsoft Entra Conditional Access (CA)** policy templates and an automated PowerShell deployment script. It is designed to help organizations rapidly deploy a **baseline of security policies**, especially those enforcing **Multi-Factor Authentication (MFA)**, across their Azure AD (Microsoft Entra ID) environment.

---

## 📘 Overview

Conditional Access is a feature of Azure Active Directory (Entra ID) that allows organizations to enforce access control policies based on user context (e.g., identity, device, location, risk). This repository automates the deployment of predefined Conditional Access policies using:

- JSON templates defining each policy
- A PowerShell script that authenticates and deploys the policies via Microsoft Graph API

---

## 🧾 Microsoft Licensing Requirements

To use Conditional Access policies, your tenant must be licensed appropriately.

| Feature                       | Required License                                |
|------------------------------|--------------------------------------------------|
| Basic Conditional Access     | Azure AD Premium P1 (included in Microsoft 365 E3) |
| Risk-based Conditional Access| Azure AD Premium P2 (included in Microsoft 365 E5) |
| Named Locations & Device Filters | Azure AD Premium P1/P2                        |
| Report-Only Mode             | Azure AD Premium P1                              |

For production use of this repository, you need:
- **Microsoft Entra ID P1** or **Microsoft 365 E3** minimum
- **Microsoft Graph API** permissions via an App Registration or interactive login

- Each `CAxxx_Require_MFA_Variation_XX.json` defines a policy variation with specific targeting logic, such as:
  - Users: Admins, guests, or all users
  - Conditions: Risk-based, device compliance, named locations
  - Applications: Office 365, Exchange, SharePoint, or all cloud apps
  - Grant Controls: Require MFA, compliant device, or hybrid-joined

- `deploy_ca_policies.ps1` automates the deployment of all JSON policies.

---

## ⚙️ How It Works

1. The script reads all `.json` files in the directory.
2. Each JSON is submitted as a Conditional Access policy to Microsoft Graph API.
3. Policies can be deployed in **report-only** mode or **enabled** based on your settings.

You can customize the script to:
- Apply only selected policies
- Deploy in report-only mode for testing
- Log success or failure of each deployment

---

## 🚀 Getting Started

### ✅ Prerequisites

- PowerShell 7+
- AzureAD or Microsoft.Graph PowerShell module installed
- Sufficient admin permissions (Global Admin or Security Admin)
- Optional: Azure App Registration with `Policy.ReadWrite.ConditionalAccess` and `Directory.ReadWrite.All` permissions

### 🔧 Installation

```powershell
git clone https://github.com/your-org/CA-baseline-automated.git
cd CA-baseline-automated
```
### ▶️ Deployment
````powershell
.\deploy_ca_policies.ps1
You may be prompted to authenticate unless the script is updated to use App Registration (client secret/certificate).
````
### 📊 Recommendations
Start with report-only mode to evaluate the impact.

Use the Microsoft Entra Admin Center to review policy outcomes and sign-in logs.

Modify conditions, assignments, and controls as needed in the JSON files before production deployment.

### 📥 Contributing
Contributions are welcome! You can:

Add more policy variations

Improve automation and logging

Extend support for named locations, filters, or dynamic groups

### 📄 License
This project is licensed under the MIT License.

### 📚 Resources
Microsoft Docs – Conditional Access

Microsoft Docs – Azure AD Premium Licensing

Microsoft Graph API – Conditional Access Policies

