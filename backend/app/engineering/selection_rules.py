from dataclasses import dataclass

from app.models.product import Product
from app.schemas.selection import SelectionReason
from app.schemas.selection import SelectionRequest


@dataclass(frozen=True)
class RuleResult:
    reason: SelectionReason
    maximum_score: int


class SelectionRules:
    MEASUREMENT_SCORE = 50
    MANUFACTURER_SCORE = 15
    FAMILY_SCORE = 10
    APPLICATION_SCORE = 10
    TECHNOLOGY_SCORE = 5
    PROTOCOL_SCORE = 10

    @classmethod
    def evaluate(
        cls,
        product: Product,
        request: SelectionRequest,
    ) -> list[RuleResult]:
        return [
            cls._evaluate_measurement(
                product,
                request,
            ),
            cls._evaluate_manufacturer(
                product,
                request,
            ),
            cls._evaluate_family(
                product,
                request,
            ),
            cls._evaluate_application(
                product,
                request,
            ),
            cls._evaluate_technology(
                product,
                request,
            ),
            cls._evaluate_protocols(
                product,
                request,
            ),
        ]

    @classmethod
    def _evaluate_measurement(
        cls,
        product: Product,
        request: SelectionRequest,
    ) -> RuleResult:
        matched = (
            product.measurement_id
            == request.measurement_id
        )

        return RuleResult(
            reason=SelectionReason(
                criterion="measurement",
                matched=matched,
                score=(
                    cls.MEASUREMENT_SCORE
                    if matched
                    else 0
                ),
                explanation=(
                    "Product measurement matches the "
                    "required measurement."
                    if matched
                    else (
                        "Product measurement does not match "
                        "the required measurement."
                    )
                ),
            ),
            maximum_score=cls.MEASUREMENT_SCORE,
        )

    @classmethod
    def _evaluate_manufacturer(
        cls,
        product: Product,
        request: SelectionRequest,
    ) -> RuleResult:
        if request.manufacturer_id is None:
            return RuleResult(
                reason=SelectionReason(
                    criterion="manufacturer",
                    matched=True,
                    score=cls.MANUFACTURER_SCORE,
                    explanation=(
                        "No manufacturer preference was supplied."
                    ),
                ),
                maximum_score=cls.MANUFACTURER_SCORE,
            )

        matched = (
            product.manufacturer_id
            == request.manufacturer_id
        )

        return RuleResult(
            reason=SelectionReason(
                criterion="manufacturer",
                matched=matched,
                score=(
                    cls.MANUFACTURER_SCORE
                    if matched
                    else 0
                ),
                explanation=(
                    "Product manufacturer matches the preference."
                    if matched
                    else (
                        "Product manufacturer does not match "
                        "the preference."
                    )
                ),
            ),
            maximum_score=cls.MANUFACTURER_SCORE,
        )

    @classmethod
    def _evaluate_family(
        cls,
        product: Product,
        request: SelectionRequest,
    ) -> RuleResult:
        if request.family_id is None:
            return RuleResult(
                reason=SelectionReason(
                    criterion="family",
                    matched=True,
                    score=cls.FAMILY_SCORE,
                    explanation=(
                        "No product family preference was supplied."
                    ),
                ),
                maximum_score=cls.FAMILY_SCORE,
            )

        matched = product.family_id == request.family_id

        return RuleResult(
            reason=SelectionReason(
                criterion="family",
                matched=matched,
                score=(
                    cls.FAMILY_SCORE
                    if matched
                    else 0
                ),
                explanation=(
                    "Product family matches the preference."
                    if matched
                    else (
                        "Product family does not match "
                        "the preference."
                    )
                ),
            ),
            maximum_score=cls.FAMILY_SCORE,
        )

    @classmethod
    def _evaluate_application(
        cls,
        product: Product,
        request: SelectionRequest,
    ) -> RuleResult:
        if request.application_id is None:
            return RuleResult(
                reason=SelectionReason(
                    criterion="application",
                    matched=True,
                    score=cls.APPLICATION_SCORE,
                    explanation=(
                        "No application preference was supplied."
                    ),
                ),
                maximum_score=cls.APPLICATION_SCORE,
            )

        matched = (
            product.application_id
            == request.application_id
        )

        return RuleResult(
            reason=SelectionReason(
                criterion="application",
                matched=matched,
                score=(
                    cls.APPLICATION_SCORE
                    if matched
                    else 0
                ),
                explanation=(
                    "Product application matches the requirement."
                    if matched
                    else (
                        "Product application does not match "
                        "the requirement."
                    )
                ),
            ),
            maximum_score=cls.APPLICATION_SCORE,
        )

    @classmethod
    def _evaluate_technology(
        cls,
        product: Product,
        request: SelectionRequest,
    ) -> RuleResult:
        if request.technology_id is None:
            return RuleResult(
                reason=SelectionReason(
                    criterion="technology",
                    matched=True,
                    score=cls.TECHNOLOGY_SCORE,
                    explanation=(
                        "No technology preference was supplied."
                    ),
                ),
                maximum_score=cls.TECHNOLOGY_SCORE,
            )

        matched = (
            product.technology_id
            == request.technology_id
        )

        return RuleResult(
            reason=SelectionReason(
                criterion="technology",
                matched=matched,
                score=(
                    cls.TECHNOLOGY_SCORE
                    if matched
                    else 0
                ),
                explanation=(
                    "Product technology matches the preference."
                    if matched
                    else (
                        "Product technology does not match "
                        "the preference."
                    )
                ),
            ),
            maximum_score=cls.TECHNOLOGY_SCORE,
        )

    @classmethod
    def _evaluate_protocols(
        cls,
        product: Product,
        request: SelectionRequest,
    ) -> RuleResult:
        if not request.protocol_ids:
            return RuleResult(
                reason=SelectionReason(
                    criterion="protocols",
                    matched=True,
                    score=cls.PROTOCOL_SCORE,
                    explanation=(
                        "No communication protocol was required."
                    ),
                ),
                maximum_score=cls.PROTOCOL_SCORE,
            )

        product_protocol_ids = {
            protocol.id
            for protocol in product.protocols
        }

        required_protocol_ids = set(
            request.protocol_ids
        )

        matched = required_protocol_ids.issubset(
            product_protocol_ids
        )

        return RuleResult(
            reason=SelectionReason(
                criterion="protocols",
                matched=matched,
                score=(
                    cls.PROTOCOL_SCORE
                    if matched
                    else 0
                ),
                explanation=(
                    "Product supports all required protocols."
                    if matched
                    else (
                        "Product does not support all required "
                        "protocols."
                    )
                ),
            ),
            maximum_score=cls.PROTOCOL_SCORE,
        )
