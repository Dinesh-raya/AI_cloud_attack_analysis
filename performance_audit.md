# System Performance & Scalability Context

## Executive Summary
**Current Status**: Prototype-Grade.
**Scalability**: Linear to Quadratic (O(N) - O(N²)).
**Bottlenecks**: Resource Graph construction (lookups) and Fix Prioritization (path explosion).
**Recommendation**: Optimized lookup tables and stricter path limits needed for >1000 resources.

---

## 1. Complexity Analysis (Big-O)

| Component | Operation | Complexity | Analysis |
|:---|:---|:---|:---|
| **Parser** | File I/O & HCL Parsing | O(F * L) | F=Files, L=Lines. `python-hcl2` is pure Python and slow. Memory usage is high as it loads full AST. |
| **GraphBuilder** | `_find_resource_by_name` | **O(N²)** | **CRITICAL**. For every resource (N), we scan all other resources (N) to resolve references (e.g., S3 bucket names). |
| **GraphBuilder** | Edge Construction | O(N) | Once lookups are fast, iterating through attributes is linear. |
| **AttackEngine** | `_check_permission` | O(N * P) | N=Nodes, P=Policies. Iterating all nodes against all policies is heavy but necessary for permissions. |
| **FixEngine** | `calculate_fix_order` | **O(V!)** | **CRITICAL**. `nx.all_simple_paths` is exponential in worst case (fully connected). Bounded by `cutoff=10`, but branching factor still kills performance. |

---

## 2. Identified Bottlenecks

### A. Graph Builder Lookups (The N² Problem)
**Location**: `GraphBuilder._find_resource_by_name`
**Issue**: A list scan is performed for every potential relationship.
**Impact**:
- 100 Resources: 10,000 checks (Instant)
- 1,000 Resources: 1,000,000 checks (~1-2s)
- 5,000 Resources: 25,000,000 checks (~30s+)
**Fix**: Implement `O(1)` Hash Map Indexing for Names and IDs.

### B. Fix Engine Path Explosion
**Location**: `FixEngine._find_all_paths`
**Issue**: Finding *all* paths is computationally expensive for highly entangled graphs (e.g., rigid IAM hierarchy).
**Impact**: Memory exhaustion on large graphs with many redundant paths.
**Fix**: Cap the number of paths analyzed (e.g., `max_paths=100`) or use flow-based algorithms (Max-Flow Min-Cut) instead of path enumeration.

### C. Memory Footprint
**Issue**: `Resource` objects store full raw attributes dictionary.
**Impact**: Large Terraform states (>50MB text) will consume significant RAM (>500MB) due to Python object overhead.
**Fix**: Store only relevant attributes or use `__slots__` in Data Classes.

---

## 3. Safe Limits for Real Usage

| Metric | Safe Limit (Current) | Safe Limit (Optimized) |
|:---|:---|:---|
| **Total Resources** | ~500 | ~10,000 |
| **Attack Paths** | < 1,000 | < 100,000 |
| **Execution Time** | < 10s | < 30s |

## 4. Optimization Plan
1.  **GraphBuilder**: Introduce `self.name_index` and `self.bucket_index` to make lookups O(1).
2.  **FixEngine**: Add a hard limit to `all_simple_paths` generator consumption.
