"""
Engineer4Me Engineering Knowledge Ingestion Package.

This package provides the document ingestion pipeline responsible for
converting engineering documentation into structured engineering
knowledge that can be consumed by the recommendation engine,
knowledge API and future AI services.

Pipeline:

Document
    ↓
Parser
    ↓
Metadata Extraction
    ↓
Engineering Extraction
    ↓
Knowledge Object Generation
    ↓
Evidence Linking
    ↓
Duplicate Detection
    ↓
Review Workflow
    ↓
Repository Publishing
"""