from app.engineering.selection_rules import SelectionRules
from app.models.product import Product
from app.schemas.selection import ProductRecommendation
from app.schemas.selection import SelectionRequest


class RecommendationEngine:
    @staticmethod
    def recommend(
        products: list[Product],
        request: SelectionRequest,
    ) -> list[ProductRecommendation]:
        recommendations: list[ProductRecommendation] = []

        for product in products:
            rule_results = SelectionRules.evaluate(
                product,
                request,
            )

            score = sum(
                result.reason.score
                for result in rule_results
            )

            maximum_score = sum(
                result.maximum_score
                for result in rule_results
            )

            match_percentage = (
                round(
                    score / maximum_score * 100,
                    2,
                )
                if maximum_score > 0
                else 0.0
            )

            if match_percentage < request.minimum_score:
                continue

            recommendations.append(
                ProductRecommendation(
                    product_id=product.id,
                    manufacturer=product.manufacturer.name,
                    family=product.family.name,
                    model=product.model,
                    description=product.description,
                    score=score,
                    maximum_score=maximum_score,
                    match_percentage=match_percentage,
                    reasons=[
                        result.reason
                        for result in rule_results
                    ],
                )
            )

        recommendations.sort(
            key=lambda recommendation: (
                -recommendation.match_percentage,
                recommendation.manufacturer.lower(),
                recommendation.model.lower(),
            )
        )

        return recommendations[: request.limit]
