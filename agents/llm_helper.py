from langchain_ollama import OllamaLLM
from langchain_core.prompts import PromptTemplate


class LLMHelper:
    def __init__(self, model_name: str = "mistral"):
        self.llm = OllamaLLM(model=model_name, temperature=0.3)

        self.prompt_template = PromptTemplate(
            input_variables=[
                "event_type", "source_ip", "attack_type",
                "severity", "indicators", "count"
            ],
            template="""Tu es un analyste SOC (Security Operations Center) expert en cybersécurité.

Voici un événement de sécurité détecté :
- Type d'événement : {event_type}
- IP source : {source_ip}
- Type d'attaque identifié : {attack_type}
- Niveau de criticité : {severity}
- Occurrences : {count}
- Indicateurs détectés : {indicators}

Rédige une explication claire et professionnelle (3-4 phrases maximum) de cet incident de sécurité,
comme si tu rédigeais un rapport pour ton équipe. Explique ce qui s'est passé, pourquoi c'est dangereux,
et reste factuel. Réponds uniquement avec l'explication, sans introduction ni formules de politesse."""
        )

    def generer_explication(self, event: dict, analysis: dict) -> str:
        """Génère une explication en langage naturel via Mistral"""
        try:
            prompt = self.prompt_template.format(
                event_type=event["event_type"],
                source_ip=event.get("source", {}).get("ip", "unknown"),
                attack_type=analysis["attack_type"],
                severity=analysis["severity"],
                indicators=", ".join(analysis["indicators"]),
                count=event.get("count", 1)
            )
            response = self.llm.invoke(prompt)
            return response.strip()
        except Exception as e:
            print(f"[LLMHelper] Erreur génération explication: {e}")
            return "Explication non disponible (erreur LLM)."