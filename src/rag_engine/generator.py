"""
响应生成器 - 基于检索结果生成高质量回答
"""
from typing import List, Dict, Any, Optional
from loguru import logger
from ..llm.deepseek_client import DeepSeekClient
from ..utils.config import get_settings


class ResponseGenerator:
    """响应生成器"""
    
    def __init__(self, llm_client: DeepSeekClient = None):
        """
        初始化响应生成器
        
        Args:
            llm_client: LLM客户端
        """
        self.settings = get_settings()
        self.llm = llm_client or DeepSeekClient(
            api_key=self.settings.deepseek_api_key,
            base_url=self.settings.deepseek_base_url
        )
        
        # 生成配置
        self.max_context_length = 8000
        self.max_response_tokens = 2048
        self.temperature = 0.1
    
    def generate_response(
        self,
        query: str,
        retrieved_contexts: List[Dict[str, Any]],
        response_type: str = "comprehensive",
        include_sources: bool = True
    ) -> Dict[str, Any]:
        """
        生成响应
        
        Args:
            query: 用户查询
            retrieved_contexts: 检索到的上下文
            response_type: 响应类型 ("brief", "comprehensive", "analytical")
            include_sources: 是否包含来源信息
            
        Returns:
            生成的响应和元数据
        """
        try:
            # 处理和过滤上下文
            processed_contexts = self._process_contexts(retrieved_contexts)
            
            # 构建提示词
            prompt = self._build_prompt(query, processed_contexts, response_type)
            
            # 生成响应
            if response_type == "analytical":
                response = self._generate_analytical_response(prompt)
            else:
                response = self.llm.generate_text(
                    prompt,
                    max_tokens=self.max_response_tokens,
                    temperature=self.temperature
                )
            
            # 后处理和验证
            final_response = self._post_process_response(response, query, processed_contexts)
            
            # 构建结果
            result = {
                'response': final_response,
                'query': query,
                'response_type': response_type,
                'context_count': len(processed_contexts),
                'metadata': {
                    'sources_used': len(set(ctx.get('source', '') for ctx in processed_contexts)),
                    'retrieval_methods': list(set(ctx.get('retrieval_source', '') for ctx in processed_contexts)),
                    'confidence_score': self._calculate_confidence(processed_contexts)
                }
            }
            
            if include_sources:
                result['sources'] = self._extract_sources(processed_contexts)
            
            return result
            
        except Exception as e:
            logger.error(f"生成响应失败: {str(e)}")
            return {
                'response': '抱歉，无法生成回答。请稍后重试。',
                'error': str(e)
            }
    
    def generate_threat_analysis(
        self,
        query: str,
        retrieved_contexts: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        生成威胁分析报告
        
        Args:
            query: 分析请求
            retrieved_contexts: 检索到的威胁情报
            
        Returns:
            威胁分析报告
        """
        try:
            # 专门的威胁分析提示词
            prompt = self._build_threat_analysis_prompt(query, retrieved_contexts)
            
            # 生成分析报告
            analysis = self.llm.generate_text(
                prompt,
                max_tokens=4096,
                temperature=0.1
            )
            
            # 提取结构化信息
            threat_indicators = self._extract_threat_indicators(retrieved_contexts)
            
            return {
                'analysis': analysis,
                'threat_indicators': threat_indicators,
                'risk_level': self._assess_risk_level(retrieved_contexts),
                'recommendations': self._generate_recommendations(retrieved_contexts),
                'sources': self._extract_sources(retrieved_contexts)
            }
            
        except Exception as e:
            logger.error(f"生成威胁分析失败: {str(e)}")
            return {'error': str(e)}
    
    def generate_ioc_report(
        self,
        ioc_value: str,
        retrieved_contexts: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        生成IoC分析报告
        
        Args:
            ioc_value: IoC值
            retrieved_contexts: 相关上下文
            
        Returns:
            IoC分析报告
        """
        try:
            prompt = f"""
作为威胁情报分析师，请基于以下信息为IoC指标 {ioc_value} 生成详细的分析报告：

相关威胁情报：
{self._format_contexts_for_prompt(retrieved_contexts)}

请从以下方面进行分析：
1. IoC基本信息和类型
2. 威胁等级评估
3. 关联的恶意活动
4. 相关APT组织或攻击者
5. 攻击技术和战术
6. 影响范围和目标
7. 检测和防护建议
8. 时间线分析（如有）

请提供专业、准确的分析，格式清晰。
"""
            
            report = self.llm.generate_text(
                prompt,
                max_tokens=3072,
                temperature=0.1
            )
            
            return {
                'ioc_value': ioc_value,
                'report': report,
                'threat_level': self._assess_ioc_threat_level(retrieved_contexts),
                'associated_malware': self._extract_associated_malware(retrieved_contexts),
                'apt_groups': self._extract_apt_groups(retrieved_contexts),
                'first_seen': self._extract_first_seen(retrieved_contexts),
                'sources': self._extract_sources(retrieved_contexts)
            }
            
        except Exception as e:
            logger.error(f"生成IoC报告失败: {str(e)}")
            return {'error': str(e)}
    
    def generate_summary(
        self,
        documents: List[str],
        summary_type: str = "executive"
    ) -> str:
        """
        生成文档摘要
        
        Args:
            documents: 文档列表
            summary_type: 摘要类型 ("executive", "technical", "brief")
            
        Returns:
            生成的摘要
        """
        try:
            # 合并文档内容
            combined_content = "\n\n".join(documents)
            
            # 截断过长内容
            if len(combined_content) > self.max_context_length:
                combined_content = combined_content[:self.max_context_length] + "..."
            
            if summary_type == "executive":
                prompt = f"""
请为以下威胁情报文档生成执行摘要，重点关注：
- 主要威胁和风险
- 业务影响
- 关键行动建议

文档内容：
{combined_content}

执行摘要：
"""
            elif summary_type == "technical":
                prompt = f"""
请为以下威胁情报文档生成技术摘要，重点关注：
- 技术细节和IoC指标
- 攻击技术和方法
- 检测和防护技术

文档内容：
{combined_content}

技术摘要：
"""
            else:  # brief
                prompt = f"""
请为以下威胁情报文档生成简要摘要，突出最重要的信息：

文档内容：
{combined_content}

简要摘要：
"""
            
            return self.llm.generate_text(
                prompt,
                max_tokens=1024,
                temperature=0.1
            )
            
        except Exception as e:
            logger.error(f"生成摘要失败: {str(e)}")
            return "摘要生成失败"
    
    def _process_contexts(self, contexts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """处理和过滤上下文"""
        processed = []
        total_length = 0
        
        # 按相关性排序
        sorted_contexts = sorted(
            contexts,
            key=lambda x: x.get('final_score', x.get('retrieval_score', 0)),
            reverse=True
        )
        
        for context in sorted_contexts:
            content = context.get('content', '')
            
            # 检查长度限制
            if total_length + len(content) > self.max_context_length:
                # 截断内容以适应长度限制
                remaining_length = self.max_context_length - total_length
                if remaining_length > 100:  # 至少保留100字符
                    context['content'] = content[:remaining_length] + "..."
                    processed.append(context)
                break
            
            processed.append(context)
            total_length += len(content)
        
        return processed
    
    def _build_prompt(
        self,
        query: str,
        contexts: List[Dict[str, Any]],
        response_type: str
    ) -> str:
        """构建提示词"""
        context_text = self._format_contexts_for_prompt(contexts)
        
        if response_type == "brief":
            system_prompt = "你是一个威胁情报分析专家。请基于提供的上下文简洁地回答问题。"
        elif response_type == "comprehensive":
            system_prompt = "你是一个威胁情报分析专家。请基于提供的上下文详细地回答问题，包含相关的技术细节和分析。"
        else:  # analytical
            system_prompt = "你是一个威胁情报分析专家。请基于提供的上下文进行深入分析，提供专业的威胁评估和建议。"
        
        prompt = f"""{system_prompt}

基于以下威胁情报信息回答问题：

{context_text}

问题：{query}

请提供准确、专业的回答："""
        
        return prompt
    
    def _build_threat_analysis_prompt(
        self,
        query: str,
        contexts: List[Dict[str, Any]]
    ) -> str:
        """构建威胁分析提示词"""
        context_text = self._format_contexts_for_prompt(contexts)
        
        prompt = f"""
作为高级威胁情报分析师，请基于以下信息进行威胁分析：

威胁情报数据：
{context_text}

分析请求：{query}

请提供结构化的威胁分析报告，包含：

## 威胁概述
- 威胁类型和严重程度
- 主要威胁行为者

## 技术分析
- 攻击技术和战术（MITRE ATT&CK框架）
- IoC指标分析
- 恶意软件分析

## 影响评估
- 潜在目标和影响范围
- 业务风险评估

## 防护建议
- 检测规则建议
- 防护措施建议
- 应急响应建议

## 时间线分析
- 攻击活动时间线
- 威胁演进趋势

请确保分析专业、准确、可操作。
"""
        
        return prompt
    
    def _generate_analytical_response(self, prompt: str) -> str:
        """生成分析性响应"""
        try:
            # 使用更高的token限制进行深度分析
            response = self.llm.generate_text(
                prompt,
                max_tokens=4096,
                temperature=0.05  # 更低的温度确保更准确的分析
            )
            
            return response
            
        except Exception as e:
            logger.error(f"生成分析性响应失败: {str(e)}")
            return "分析生成失败，请稍后重试。"
    
    def _format_contexts_for_prompt(self, contexts: List[Dict[str, Any]]) -> str:
        """格式化上下文用于提示词"""
        formatted_contexts = []
        
        for i, context in enumerate(contexts, 1):
            content = context.get('content', '')
            source = context.get('metadata', {}).get('source', '未知来源')
            retrieval_source = context.get('retrieval_source', '未知')
            
            formatted = f"""
--- 信息片段 {i} (来源: {source}, 检索方式: {retrieval_source}) ---
{content}
"""
            formatted_contexts.append(formatted)
        
        return "\n".join(formatted_contexts)
    
    def _post_process_response(
        self,
        response: str,
        query: str,
        contexts: List[Dict[str, Any]]
    ) -> str:
        """后处理响应"""
        # 移除可能的格式错误
        response = response.strip()
        
        # 如果响应过短，尝试重新生成
        if len(response) < 50:
            logger.warning("响应过短，可能生成失败")
            return f"基于检索到的 {len(contexts)} 条威胁情报信息，无法生成详细回答。请尝试更具体的问题。"
        
        # 检查是否包含不当内容（基本检查）
        if "无法回答" in response and len(contexts) > 0:
            return f"基于检索到的威胁情报信息：\n\n{response}"
        
        return response
    
    def _calculate_confidence(self, contexts: List[Dict[str, Any]]) -> float:
        """计算响应置信度"""
        if not contexts:
            return 0.0
        
        # 基于检索结果的数量和质量计算置信度
        total_score = sum(
            ctx.get('final_score', ctx.get('retrieval_score', 0))
            for ctx in contexts
        )
        
        avg_score = total_score / len(contexts)
        context_diversity = len(set(ctx.get('retrieval_source', '') for ctx in contexts))
        
        # 综合评分
        confidence = min(1.0, avg_score * 0.7 + (context_diversity / 3) * 0.3)
        return round(confidence, 2)
    
    def _extract_sources(self, contexts: List[Dict[str, Any]]) -> List[Dict[str, str]]:
        """提取来源信息"""
        sources = []
        seen_sources = set()
        
        for context in contexts:
            metadata = context.get('metadata', {})
            source = metadata.get('source', '')
            
            if source and source not in seen_sources:
                sources.append({
                    'source': source,
                    'type': metadata.get('file_type', '未知'),
                    'retrieval_method': context.get('retrieval_source', '未知')
                })
                seen_sources.add(source)
        
        return sources
    
    def _extract_threat_indicators(self, contexts: List[Dict[str, Any]]) -> Dict[str, List[str]]:
        """提取威胁指标"""
        indicators = {
            'iocs': [],
            'malware': [],
            'apt_groups': [],
            'cves': [],
            'techniques': []
        }
        
        for context in contexts:
            metadata = context.get('metadata', {})
            
            # 从元数据中提取
            if metadata.get('entity_type') == 'ioc':
                indicators['iocs'].append(metadata.get('entity_value', ''))
            elif metadata.get('entity_type') == 'apt':
                indicators['apt_groups'].append(metadata.get('entity_value', ''))
            elif metadata.get('entity_type') == 'malware':
                indicators['malware'].append(metadata.get('entity_value', ''))
            
            # 从内容中提取（简单正则匹配）
            content = context.get('content', '')
            
            import re
            # CVE匹配
            cves = re.findall(r'CVE-\d{4}-\d{4,}', content, re.IGNORECASE)
            indicators['cves'].extend(cves)
            
            # MITRE技术匹配
            techniques = re.findall(r'T\d{4}(?:\.\d{3})?', content)
            indicators['techniques'].extend(techniques)
        
        # 去重
        for key in indicators:
            indicators[key] = list(set(indicators[key]))
        
        return indicators
    
    def _assess_risk_level(self, contexts: List[Dict[str, Any]]) -> str:
        """评估风险等级"""
        high_risk_indicators = ['ransomware', 'apt', 'zero-day', 'critical']
        medium_risk_indicators = ['malware', 'phishing', 'vulnerability']
        
        content_text = ' '.join([ctx.get('content', '').lower() for ctx in contexts])
        
        high_count = sum(1 for indicator in high_risk_indicators if indicator in content_text)
        medium_count = sum(1 for indicator in medium_risk_indicators if indicator in content_text)
        
        if high_count >= 2:
            return "高风险"
        elif high_count >= 1 or medium_count >= 3:
            return "中风险"
        elif medium_count >= 1:
            return "低风险"
        else:
            return "信息不足"
    
    def _generate_recommendations(self, contexts: List[Dict[str, Any]]) -> List[str]:
        """生成防护建议"""
        recommendations = []
        
        content_text = ' '.join([ctx.get('content', '').lower() for ctx in contexts])
        
        # 基于内容关键词生成建议
        if 'phishing' in content_text:
            recommendations.append("加强邮件安全过滤和用户安全意识培训")
        
        if 'ransomware' in content_text:
            recommendations.append("确保数据备份完整性并测试恢复流程")
        
        if 'vulnerability' in content_text or 'cve' in content_text:
            recommendations.append("及时安装安全补丁并进行漏洞扫描")
        
        if 'apt' in content_text:
            recommendations.append("实施高级威胁检测和响应措施")
        
        if not recommendations:
            recommendations.append("加强网络安全监控和日志分析")
        
        return recommendations
    
    def _assess_ioc_threat_level(self, contexts: List[Dict[str, Any]]) -> str:
        """评估IoC威胁等级"""
        # 基于检索结果的数量和质量评估
        if len(contexts) >= 5:
            return "高威胁"
        elif len(contexts) >= 2:
            return "中威胁"
        elif len(contexts) >= 1:
            return "低威胁"
        else:
            return "未知"
    
    def _extract_associated_malware(self, contexts: List[Dict[str, Any]]) -> List[str]:
        """提取关联恶意软件"""
        malware = []
        
        for context in contexts:
            metadata = context.get('metadata', {})
            if metadata.get('entity_type') == 'malware':
                malware.append(metadata.get('entity_value', ''))
        
        return list(set(malware))
    
    def _extract_apt_groups(self, contexts: List[Dict[str, Any]]) -> List[str]:
        """提取APT组织"""
        apt_groups = []
        
        for context in contexts:
            metadata = context.get('metadata', {})
            if metadata.get('entity_type') == 'apt':
                apt_groups.append(metadata.get('entity_value', ''))
        
        return list(set(apt_groups))
    
    def _extract_first_seen(self, contexts: List[Dict[str, Any]]) -> Optional[str]:
        """提取首次发现时间"""
        for context in contexts:
            content = context.get('content', '')
            # 简单的时间提取逻辑
            import re
            dates = re.findall(r'\d{4}-\d{2}-\d{2}', content)
            if dates:
                return min(dates)
        
        return None 