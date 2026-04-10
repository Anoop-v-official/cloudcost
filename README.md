<p align="center">
  <h1 align="center">☁️ CloudCost</h1>
  <p align="center">
    <strong>Find hidden money in your AWS account in seconds.</strong>
  </p>
  <p align="center">
    <a href="#installation">Installation</a> •
    <a href="#quick-start">Quick Start</a> •
    <a href="#what-it-scans">Scanners</a> •
    <a href="#sample-output">Sample Output</a> •
    <a href="#roadmap">Roadmap</a>
  </p>
</p>

---

CloudCost is an open-source CLI tool that scans your AWS infrastructure and finds cost optimization opportunities — unused resources, oversized instances, idle databases, and forgotten snapshots that are silently draining your budget.

## Why CloudCost?

Most teams don't realize they're overspending until the monthly bill arrives. CloudCost catches waste the moment you run it:

- 🔍 **11 scanners** covering EC2, EBS, RDS, EKS, S3, Lambda, ElastiCache, and more
- ⚡ **Right-sizing analysis** with 14-day CPU/memory metrics
- 🕐 **Auto-stop/start recommendations** for dev/staging environments
- 🔧 **Copy-paste CLI commands** to fix every issue instantly
- 🔒 **Read-only** — CloudCost never modifies your infrastructure

## What It Scans

| Scanner | What It Catches | Example Savings |
|---|---|---|
| **EBS Volumes** | Unattached volumes, gp2→gp3 conversion, oversized storage | $77/mo for forgotten 800GB volume |
| **EBS Snapshots** | Old/large snapshots, archive candidates | $70/mo for 1.5TB snapshot |
| **EC2 Instances** | Underutilized (CPU <20%), stopped with EBS costs | $140/mo oversized instance |
| **Elastic IPs** | Unattached IPs ($3.60/mo each) | $11/mo for 3 unused IPs |
| **Load Balancers** | Zero healthy targets, orphaned target groups | $40/mo for idle NLBs |
| **NAT Gateways** | Unnecessary NAT ($32+/mo base) | $25/mo if instances have public IPs |
| **RDS / DocumentDB** | Idle databases (0 connections), oversized instances | $167/mo for unused DocumentDB |
| **EKS Clusters** | Idle clusters ($73/mo control plane), zero-node groups | $103/mo for forgotten cluster |
| **S3 Buckets** | Versioning without lifecycle, missing intelligent tiering | Varies |
| **Lambda** | Unused functions (0 invocations), oversized memory | Varies |
| **CloudWatch Logs** | No retention policy (logs kept forever) | $10-50/mo in log storage |
| **ElastiCache** | Idle Redis/Memcached clusters | $50+/mo for unused cache |
| **Right-Sizing** | Over-provisioned instances with day/night CPU analysis | $22/mo downsize + schedule |
| **Scheduling** | Dev/staging instances running 24/7 unnecessarily | 35% savings with auto-stop |

## Installation

### Prerequisites
- Go 1.22 or later
- AWS CLI configured with credentials

### From source

```bash
git clone https://github.com/YOUR_USERNAME/cloudcost.git
cd cloudcost
go mod tidy
make build
```

The binary will be at `./dist/cloudcost`.

### Install globally

```bash
make install
```

## Quick Start

### 1. Set up a read-only IAM user (recommended)

```bash
aws iam create-user --user-name cloudcost-reader

aws iam put-user-policy --user-name cloudcost-reader \
  --policy-name CloudCostReadOnly \
  --policy-document file://iam-policy.json

aws iam create-access-key --user-name cloudcost-reader
```

### 2. Configure AWS profile

```bash
aws configure --profile cloudcost
# Enter the access key and secret from above
```

### 3. Run your first scan

```bash
cloudcost scan --profile cloudcost --region us-east-1
```

That's it. You'll see a color-coded report with every finding, savings amount, and the exact CLI command to fix it.

## Usage

```bash
# Scan with default AWS profile
cloudcost scan

# Scan specific profile and region
cloudcost scan --profile myprofile --region us-east-1

# Scan all major AWS regions
cloudcost scan --profile myprofile --all-regions

# Output as JSON
cloudcost scan --profile myprofile --output json

# Save report to file
cloudcost scan --profile myprofile --save report.json

# Cross-account scan via IAM role
cloudcost scan --role-arn arn:aws:iam::123456789012:role/CloudCostReadOnly

# Custom thresholds
cloudcost scan --snapshot-age 60 --ami-age 180
```

## Sample Output

```
  ☁️  CloudCost Scanner
  Finding money hiding in your AWS account...

  📋 Account: 123456789012
  👤 Profile: myprofile
  🌍 Regions: [us-east-1]

    📦 Scanning EBS volumes & snapshots... ✓
    🖥️  Scanning EC2 instances & IPs... ✓
    🌐 Scanning Load Balancers & NAT Gateways... ✓
    ⚡ Analyzing instance right-sizing... ✓
    🕐 Detecting auto-stop/start candidates... ✓
    🗄️  Scanning RDS & DocumentDB... ✓
    ☸️  Scanning EKS clusters... ✓
    🪣 Scanning S3 buckets... ✓
    ⚡ Scanning Lambda functions... ✓
    📝 Scanning CloudWatch Log groups... ✓
    🔴 Scanning ElastiCache clusters... ✓

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  ☁️  CloudCost Report — Account: 123456789012
  Scanned: 2026-04-10 12:00:00
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  💰 Total Potential Savings: $312.00/month ($3,744.00/year)
  📊 Findings: 8 total | 2 critical | 3 high | 2 medium | 1 low

  🔴 CRITICAL — Act Now (save $244.00/mo)
  ────────────────────────────────────────
  1. Idle DocumentDB cluster (0 connections)                   $167.00/mo
     my-docdb-cluster [us-east-1]
     → Delete the cluster if no longer needed

  2. Unattached EBS volume (800 GB, gp3)                        $76.80/mo
     vol-0abc123def456 [us-east-1]
     → Delete the volume

  🟡 HIGH — Recommended (save $52.00/mo)
  ────────────────────────────────────────
  3. Over-provisioned: staging-server (t3.xlarge → t3.medium)   $42.00/mo
     i-0abc123def456 [us-east-1]
     → Downsize from t3.xlarge to t3.medium

  4. 3 unused Elastic IPs                                       $10.80/mo
     → Release unattached Elastic IPs
```

## Required IAM Permissions

CloudCost needs **read-only** access. It never creates, modifies, or deletes anything. See `iam-policy.json` for the full policy.

<details>
<summary>View full IAM policy</summary>

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeVolumes",
        "ec2:DescribeSnapshots",
        "ec2:DescribeInstances",
        "ec2:DescribeAddresses",
        "ec2:DescribeImages",
        "ec2:DescribeNatGateways",
        "elasticloadbalancing:DescribeLoadBalancers",
        "elasticloadbalancing:DescribeTargetGroups",
        "elasticloadbalancing:DescribeTargetHealth",
        "cloudwatch:GetMetricStatistics",
        "sts:GetCallerIdentity",
        "rds:DescribeDBInstances",
        "rds:DescribeDBClusters",
        "eks:ListClusters",
        "eks:DescribeCluster",
        "eks:ListNodegroups",
        "eks:DescribeNodegroup",
        "s3:ListAllMyBuckets",
        "s3:GetBucketLocation",
        "s3:GetBucketVersioning",
        "s3:GetLifecycleConfiguration",
        "lambda:ListFunctions",
        "logs:DescribeLogGroups",
        "elasticache:DescribeCacheClusters"
      ],
      "Resource": "*"
    }
  ]
}
```

</details>

## Project Structure

```
cloudcost/
├── cmd/cli/main.go              # CLI entry point
├── internal/
│   ├── config/aws.go            # AWS configuration & cross-account access
│   ├── models/finding.go        # Data structures & pricing
│   ├── reporter/terminal.go     # Color-coded terminal output
│   └── scanner/
│       ├── ebs.go               # EBS volumes & snapshots
│       ├── ec2.go               # EC2 instances, EIPs, AMIs
│       ├── eks.go               # EKS clusters & node groups
│       ├── elasticache.go       # ElastiCache clusters
│       ├── cloudwatch.go        # CloudWatch log groups
│       ├── lambda.go            # Lambda functions
│       ├── network.go           # Load Balancers, NAT Gateways
│       ├── rds.go               # RDS & DocumentDB
│       ├── rightsize.go         # Over-provisioned instance detection
│       ├── s3.go                # S3 buckets & lifecycle
│       └── schedule.go          # Auto-stop/start candidates
├── iam-policy.json              # Minimum IAM permissions
├── Makefile
├── go.mod
└── LICENSE
```

## How It Works

1. **Connects** to your AWS account using your configured credentials (read-only)
2. **Scans** 11 resource types using AWS APIs and CloudWatch metrics
3. **Analyzes** utilization patterns over 7-14 days (CPU, connections, traffic)
4. **Reports** findings sorted by severity with exact monthly savings
5. **Provides** copy-paste CLI commands to fix each issue

CloudCost uses only `Describe*`, `List*`, and `Get*` API calls. It will never create, modify, or delete any resource in your account.

## Roadmap

- [x] EBS volume & snapshot scanner
- [x] EC2 instance & EIP scanner
- [x] Load Balancer & NAT Gateway scanner
- [x] Right-sizing with CPU analysis
- [x] Auto-stop/start scheduling recommendations
- [x] RDS & DocumentDB scanner
- [x] EKS cluster scanner
- [x] S3 bucket analysis
- [x] Lambda function scanner
- [x] CloudWatch Logs scanner
- [x] ElastiCache scanner
- [ ] AI-powered analysis
- [ ] HTML report export
- [ ] Slack/Email notifications
- [ ] Multi-cloud support (GCP, Azure)
- [ ] Web dashboard (SaaS)

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/new-scanner`)
3. Commit your changes (`git commit -m 'Add new scanner'`)
4. Push to the branch (`git push origin feature/new-scanner`)
5. Open a Pull Request

## License

MIT License — see [LICENSE](LICENSE) for details.
