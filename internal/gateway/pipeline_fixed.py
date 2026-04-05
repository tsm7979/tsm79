    async def _firewall_layer(self, input_text: str, context: Dict) -> tuple:
        """Layer 3: Firewall - Sanitize and classify"""
        from firewall import sanitizer, classifier

        # Sanitize (sync function)
        result = sanitizer.sanitize(input_text)
        sanitized = result.sanitized_text

        # Classify (async function)
        risk = await classifier.classify(sanitized, context, result)

        return sanitized, risk
