# Causal AI & Probabilistic Diagnostic Engines Architecture

This document outlines the mathematical principles, algorithm designs, and subsystem implementations powering Eldar Jamiyev's Infrastructure Intelligence (EJII) causal diagnostic and AI engines.

---

## 1. Structural Causal Models & Pearlian $do$-Calculus

### Formal Definition
Infrastructure systems are formalized as a directed acyclic causal graph $G = (V, E)$, where endogenous state variables $X_i \in V$ (e.g. packet arrival rate $\lambda$, buffer queue depth $q$, round-trip time $\text{RTT}$, packet loss percentage) are determined by structural functions:
$$X_i = f_i(\text{PA}_i, U_i)$$
where $\text{PA}_i \subset V$ are direct causal parents in $G$, and $U_i$ are independent exogenous background noise variables representing unmodeled environment factors.

### Three-Step Counterfactual Algorithm
1. **Abduction**: Infer exogenous background noise $\mathbf{U}$ from factual evidence $(x, y)$:
   $$u_{\text{queue}} = q_{\text{obs}} - \frac{\lambda}{\mu - \lambda}$$
   $$u_{\text{rtt}} = \text{RTT}_{\text{obs}} - \left( \text{RTT}_{\text{prop}} + \frac{q_{\text{obs}}}{\mu} \right)$$
   $$u_{\text{loss}} = \text{loss}_{\text{obs}} - \sigma(\beta_0 + \beta_1 q_{\text{obs}} + \beta_2 \cdot \text{drop}_{\text{pol}})$$
2. **Action**: Apply graph mutilation $do(X_j = x_j')$ by removing all incoming structural arrows into $X_j$ and clamping its value to $x_j'$.
3. **Prediction**: Propagate the intervention through the mutilated DAG while retaining the abduced noise $\mathbf{U}$ to compute counterfactual outcomes ($q^*, \text{RTT}^*, \text{loss}^*$).

---

## 2. State-Adaptive Riemannian Lyapunov Energy Metric

### Formulation
To mathematically certify remediation safety without false positives near operational saturation boundaries, EJII evaluates energy via a state-dependent metric tensor $\mathbf{M}(s) \succ 0$:
$$V(s) = s^T \mathbf{M}(s) s$$
$$\mathbf{M}(s) = \mathbf{W}_0 + \sum_{k=1}^K \sigma_k(s) \mathbf{W}_k$$
where:
* $\mathbf{W}_0 = \operatorname{diag}(0.40, 0.40, 0.20)$ (strictly positive-definite base metric)
* $\sigma_k(s) = \frac{1}{1 + e^{-\alpha (s_k - \theta_k)}} \in (0, 1)$ (smooth sigmoid cliff transition)
* $\mathbf{W}_k \succeq 0$ (positive semi-definite penalty matrices for saturation thresholds $\theta_k$)

### Sylvester's Criterion Guarantee
Since $\mathbf{W}_0 \succ 0$ and $\sigma_k(s) \mathbf{W}_k \succeq 0$, their sum $\mathbf{M}(s)$ is strictly positive-definite everywhere ($V(s) > 0$ for all $s \neq 0$). A proposed action is declared stable if and only if:
$$\Delta V = V(s_{\text{post}}) - V(s_{\text{pre}}) < 0$$

---

## 3. Hierarchical Navigable Small World (HNSW) Vector Index

### Proximity Graph Architecture
* **Parameters**: $M = 16$ (bidirectional links per node), $M_0 = 32$ (ground layer links), $efConstruction = 64$ (index exploration depth), $efSearch = 32$ (query beam width).
* **Distance Metric**: Cosine distance in $\mathbb{R}^{64}$:
  $$D_{\text{cos}}(\mathbf{u}, \mathbf{v}) = 1 - \frac{\mathbf{u} \cdot \mathbf{v}}{\|\mathbf{u}\|_2 \|\mathbf{v}\|_2}$$
* **Search Complexity**: Logarithmic search time $O(\log N)$ enables real-time sub-millisecond retrieval across historical incident episodes.

---

## 4. Newman-Girvan Louvain Modularity Clustering

### Cascade Detection
To partition concurrent anomalies across topological networks into distinct fault cascades:
$$Q = \sum_{c=1}^C \left[ \frac{e_c}{2m} - \left( \frac{a_c}{2m} \right)^2 \right]$$
where $e_c$ is the number of edges inside cluster $c$, $a_c$ is the sum of degrees in cluster $c$, and $m$ is the total number of network edges. Positive modularity $Q > 0$ verifies authentic community structure and isolates distinct cascade blast radiuses.
