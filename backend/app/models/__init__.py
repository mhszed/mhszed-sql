# -*- coding: utf-8 -*-
"""模型注册中心：init_db 前必须 import 本包以注册全部表。"""
from app.models.system import User, Setting
from app.models.auth import AuthScope
from app.models.task import Task
from app.models.endpoint import Endpoint, BusinessChain
from app.models.waf import WafProfile
from app.models.assessment import RiskAssessment, ReviewAction
from app.models.scan import ScanJob
from app.models.vuln import Vulnerability, Evidence
from app.models.kb import KbPayload, KbFalsePositive, KbArticle, KbInsight
from app.models.audit import AuditLog, BurpSession
from app.models.confirmed import ConfirmedPayload

__all__ = [
    "User", "Setting", "AuthScope", "Task", "Endpoint", "BusinessChain",
    "WafProfile", "RiskAssessment", "ReviewAction", "ScanJob",
    "Vulnerability", "Evidence", "KbPayload", "KbFalsePositive",
    "KbArticle", "KbInsight",
    "AuditLog", "BurpSession", "ConfirmedPayload",
]
