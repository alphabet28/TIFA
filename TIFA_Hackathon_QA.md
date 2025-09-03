# TIFA Hackathon Project: Technical Q&A

---

## 1. How are IOCs (Indicators of Compromise) collected in TIFA?
**Answer:**
IOCs are collected using the `FeedCollector` class, which fetches threat intelligence feeds from multiple open-source and commercial sources defined in the configuration. The feeds are ingested in real-time or at scheduled intervals.

**Pros:**
- Real-time aggregation from diverse sources
- Easily extensible to add new feeds

**Cons:**
- Dependent on feed availability and format consistency
- May require frequent updates to handle new feed formats

---

## 2. How are IOCs parsed and extracted? What libraries or methods are used?
**Answer:**
IOCs are parsed using the `IOCExtractor` class, which utilizes regular expressions (regex) to identify and extract IOCs such as IPs, domains, hashes, and CVEs from raw feed data.

**Pros:**
- Fast and lightweight parsing
- Highly customizable for new IOC types

**Cons:**
- Regex can miss edge cases or obfuscated IOCs
- Maintenance required as threat actor techniques evolve

---

## 3. Why did you use Streamlit for the dashboard/UI?
**Answer:**
Streamlit was chosen for its rapid prototyping capabilities, ease of use, and ability to create interactive, data-driven dashboards with minimal frontend code.

**Pros:**
- Fast development and iteration
- Built-in support for data visualization and widgets
- Python-native, no need for separate frontend stack

**Cons:**
- Limited customization compared to React/Vue
- Not ideal for highly complex or multi-user web apps

---

## 4. Why did you deploy on Streamlit Cloud?
**Answer:**
Streamlit Cloud offers seamless deployment for Streamlit apps, with built-in support for GitHub integration, secrets management, and automatic scaling for demo and hackathon use cases.

**Pros:**
- Zero-config deployment
- Free tier suitable for hackathons and demos
- Easy sharing via public URLs

**Cons:**
- Limited resources on free tier
- Not suitable for high-traffic production workloads

---

## 5. Why did you use SQLite as the database?
**Answer:**
SQLite was selected for its simplicity, zero-configuration, and suitability for lightweight, file-based storage in single-user or small-team environments.

**Pros:**
- No server setup required
- Fast for small to medium datasets
- Portable and easy to back up

**Cons:**
- Not designed for high-concurrency or distributed workloads
- Limited scalability compared to PostgreSQL/MySQL

---

## 6. How does TIFA handle scalability?
**Answer:**
For hackathon/demo purposes, TIFA is optimized for single-instance use. For production scalability:
- The database can be migrated to PostgreSQL or another RDBMS.
- The feed collection and analysis modules can be containerized and orchestrated (e.g., with Docker/Kubernetes).
- Streamlit can be fronted by a load balancer for horizontal scaling.

**Pros:**
- Modular design allows easy migration to scalable components
- Stateless processing logic is cloud/container friendly

**Cons:**
- Requires architectural changes for true multi-user, high-availability deployments
- Streamlit’s session model is not ideal for large-scale, concurrent users

---

## 7. How is AI/ML used in TIFA?
**Answer:**
TIFA integrates Google Gemini APIs for AI-powered threat analysis, correlation, and enrichment. Multiple API keys are load-balanced for reliability.

**Pros:**
- Leverages state-of-the-art AI for threat detection
- Modular integration allows swapping AI providers

**Cons:**
- Dependent on external API availability and cost
- Requires careful handling of API limits and key management

---

## 8. How are configuration and secrets managed?
**Answer:**
Locally, `.env` files are used. On Streamlit Cloud, secrets are managed via the platform’s secure secrets manager, ensuring API keys and sensitive data are not exposed in code.

**Pros:**
- Secure and environment-specific
- Easy to update without code changes

**Cons:**
- Requires manual setup on deployment platform
- Risk of misconfiguration if not documented

---

## 9. How is error handling and fallback implemented?
**Answer:**
The app uses defensive programming:
- FallbackAggregator provides minimal functionality if the main aggregator fails.
- All metrics and database accesses are wrapped in try/except blocks to prevent crashes.

**Pros:**
- Robust against partial failures
- User always sees a working dashboard, even if degraded

**Cons:**
- Fallback mode may hide underlying issues if not monitored
- Some errors may not be visible to the user

---

## 10. How easy is it to add new threat feeds or IOC types?
**Answer:**
New feeds can be added by updating the configuration. New IOC types can be supported by extending the regex patterns in the IOCExtractor.

**Pros:**
- Highly extensible and modular
- No need to change core logic for most additions

**Cons:**
- Requires understanding of feed formats and regex
- Poorly formatted feeds may require custom parsers

---

## 11. What are the main limitations of the current architecture?
**Answer:**
- Single-user, single-instance focus
- Limited concurrency and scalability
- Streamlit session state is not persistent across users or restarts

---

## 12. How is data visualization handled?
**Answer:**
Data is visualized using Plotly and Streamlit’s built-in widgets for interactive charts, metrics, and tables.

**Pros:**
- Rich, interactive visualizations
- Easy to extend with new chart types

**Cons:**
- Some advanced visualizations may require custom JS
- Performance may degrade with very large datasets

---

## 13. How is security handled?
**Answer:**
- Secrets are never hardcoded; always managed via environment or platform secrets
- No direct user input is executed or stored without validation
- SQLite file permissions restrict access

**Cons:**
- No authentication/authorization in demo version
- For production, would need to add user management and HTTPS

---

## 14. How is code quality and maintainability ensured?
**Answer:**
- Modular code structure (src/core, src/analyzers, src/collectors, etc.)
- Logging and error handling throughout
- Type hints and docstrings for clarity

**Cons:**
- Some rapid prototyping code may need refactoring for production
- Test coverage may be limited in hackathon version

---