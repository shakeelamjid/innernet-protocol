# INNERnet main project website

The public-facing site for the protocol is **https://innernetcorp.com** (apex domain). This is intended to replace the current unrelated dummy reseller website. The primary website explains the protocol, its research status, the technical documentation, security limitations and developer tools. **Applications are secondary** and may use a dedicated page or future subdomains.

The website is built and published from a **separate public GitHub repository** `shakeelamjid/innernet-website`, not from the protocol repository, to keep static-site updates separate from security-sensitive protocol releases and source manifests.

Publication files and Mac updater are bundled separately: `INNERnet_Primary_Protocol_Website_innernetcorp.com.zip`. For deployment steps see that ZIP's `README.md`. Configure GitHub Pages custom domain `innernetcorp.com`, use verified GitHub Pages A records for the apex and a CNAME for `www`, and retain email DNS records. Updating website DNS will replace the existing dummy site only after GitHub Pages is ready. Never upload production secrets to the website repository.

Github Pages reference: https://docs.github.com/en/pages/configuring-a-custom-domain-for-your-github-pages-site/managing-a-custom-domain-for-your-github-pages-site
