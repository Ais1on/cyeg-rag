"""
混合检索器 - 结合向量检索和知识图谱查询
"""
from typing import List, Dict, Any, Optional
from loguru import logger
from ..vector_store.milvus_store import MilvusVectorStore
from ..vector_store.embedder import EmbeddingGenerator
from ..knowledge_graph.graph_query import GraphQueryEngine
from ..utils.config import get_settings


class HybridRetriever:
    """混合检索器"""
    
    def __init__(
        self,
        vector_store: MilvusVectorStore = None,
        embedder: EmbeddingGenerator = None,
        graph_query: GraphQueryEngine = None
    ):
        """
        初始化混合检索器
        
        Args:
            vector_store: 向量存储
            embedder: 嵌入生成器
            graph_query: 图查询引擎
        """
        self.settings = get_settings()
        self.vector_store = vector_store
        self.embedder = embedder
        self.graph_query = graph_query
        
        # 检索配置
        self.vector_weight = 0.6
        self.graph_weight = 0.4
        self.min_similarity_threshold = 0.3
    
    def retrieve(
        self,
        query: str,
        top_k: int = 10,
        retrieval_method: str = "hybrid",
        filters: Dict[str, Any] = None,
        expand_with_graph: bool = True
    ) -> List[Dict[str, Any]]:
        """
        执行混合检索
        
        Args:
            query: 查询文本
            top_k: 返回结果数量
            retrieval_method: 检索方法 ("vector", "graph", "hybrid")
            filters: 过滤条件
            expand_with_graph: 是否使用图谱扩展结果
            
        Returns:
            检索结果列表
        """
        try:
            if retrieval_method == "vector":
                return self._vector_retrieval(query, top_k, filters)
            elif retrieval_method == "graph":
                return self._graph_retrieval(query, top_k)
            elif retrieval_method == "hybrid":
                return self._hybrid_retrieval(query, top_k, filters, expand_with_graph)
            else:
                raise ValueError(f"不支持的检索方法: {retrieval_method}")
                
        except Exception as e:
            logger.error(f"检索失败: {str(e)}")
            return []
    
    def _vector_retrieval(
        self,
        query: str,
        top_k: int,
        filters: Dict[str, Any] = None
    ) -> List[Dict[str, Any]]:
        """向量检索"""
        try:
            if not self.vector_store or not self.embedder:
                logger.warning("向量存储或嵌入器未初始化")
                return []
            
            # 生成查询向量
            query_embedding = self.embedder.generate_embeddings(query)
            
            # 执行向量搜索
            results = self.vector_store.search(
                query_embedding=query_embedding,
                top_k=top_k,
                filter_expr=self._build_filter_expr(filters)
            )
            
            # 过滤低相似度结果
            filtered_results = [
                result for result in results
                if result['score'] >= self.min_similarity_threshold
            ]
            
            # 添加检索来源标记
            for result in filtered_results:
                result['retrieval_source'] = 'vector'
                result['retrieval_score'] = result['score']
            
            return filtered_results
            
        except Exception as e:
            logger.error(f"向量检索失败: {str(e)}")
            return []
    
    def _graph_retrieval(self, query: str, top_k: int) -> List[Dict[str, Any]]:
        """图谱检索"""
        try:
            if not self.graph_query:
                logger.warning("图查询引擎未初始化")
                return []
            
            # 提取查询中的实体
            entities = self._extract_entities_from_query(query)
            
            results = []
            
            # 基于实体查询相关信息
            for entity_type, entity_values in entities.items():
                for entity_value in entity_values:
                    if entity_type == "ioc":
                        # 查询IoC关联信息
                        ioc_info = self.graph_query.find_ioc_associations(entity_value)
                        if ioc_info:
                            results.append({
                                'content': self._format_ioc_info(ioc_info),
                                'metadata': {'entity_type': 'ioc', 'entity_value': entity_value},
                                'retrieval_source': 'graph',
                                'retrieval_score': 0.8
                            })
                    
                    elif entity_type == "apt":
                        # 查询APT组织活动
                        apt_info = self.graph_query.find_apt_campaigns(entity_value)
                        if apt_info:
                            results.append({
                                'content': self._format_apt_info(apt_info),
                                'metadata': {'entity_type': 'apt', 'entity_value': entity_value},
                                'retrieval_source': 'graph',
                                'retrieval_score': 0.8
                            })
                    
                    elif entity_type == "malware":
                        # 查询恶意软件相关信息
                        related_entities = self.graph_query.find_related_entities(
                            "Malware", entity_value, max_depth=2
                        )
                        if related_entities:
                            results.append({
                                'content': self._format_related_entities(related_entities),
                                'metadata': {'entity_type': 'malware', 'entity_value': entity_value},
                                'retrieval_source': 'graph',
                                'retrieval_score': 0.7
                            })
            
            # 如果没有找到特定实体，进行攻击模式查询
            if not results:
                attack_patterns = self.graph_query.find_attack_patterns()
                if attack_patterns:
                    for pattern in attack_patterns[:top_k]:
                        results.append({
                            'content': self._format_attack_pattern(pattern),
                            'metadata': {'entity_type': 'attack_pattern'},
                            'retrieval_source': 'graph',
                            'retrieval_score': 0.6
                        })
            
            return results[:top_k]
            
        except Exception as e:
            logger.error(f"图谱检索失败: {str(e)}")
            return []
    
    def _hybrid_retrieval(
        self,
        query: str,
        top_k: int,
        filters: Dict[str, Any] = None,
        expand_with_graph: bool = True
    ) -> List[Dict[str, Any]]:
        """混合检索"""
        try:
            # 执行向量检索
            vector_results = self._vector_retrieval(
                query, 
                int(top_k * self.vector_weight * 2),  # 获取更多向量结果用于融合
                filters
            )
            
            # 执行图谱检索
            graph_results = self._graph_retrieval(
                query, 
                int(top_k * self.graph_weight * 2)   # 获取更多图谱结果用于融合
            )
            
            # 融合结果
            merged_results = self._merge_results(vector_results, graph_results)
            
            # 图谱扩展
            if expand_with_graph and self.graph_query:
                expanded_results = self._expand_with_graph(merged_results)
                merged_results.extend(expanded_results)
            
            # 重排序和去重
            final_results = self._rerank_and_deduplicate(merged_results, query)
            
            return final_results[:top_k]
            
        except Exception as e:
            logger.error(f"混合检索失败: {str(e)}")
            return []
    
    def _extract_entities_from_query(self, query: str) -> Dict[str, List[str]]:
        """从查询中提取实体"""
        import re
        
        entities = {
            'ioc': [],
            'apt': [],
            'malware': [],
            'cve': []
        }
        
        # IP地址匹配
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        entities['ioc'].extend(re.findall(ip_pattern, query))
        
        # CVE匹配
        cve_pattern = r'CVE-\d{4}-\d{4,}'
        entities['cve'].extend(re.findall(cve_pattern, query, re.IGNORECASE))
        
        # APT组织匹配
        apt_pattern = r'\b(?:APT|apt)[\s-]?\d+\b'
        entities['apt'].extend(re.findall(apt_pattern, query, re.IGNORECASE))
        
        # 恶意软件关键词
        malware_keywords = ['malware', 'trojan', 'virus', 'ransomware', 'backdoor']
        for keyword in malware_keywords:
            if keyword.lower() in query.lower():
                entities['malware'].append(keyword)
        
        return entities
    
    def _format_ioc_info(self, ioc_info: Dict[str, Any]) -> str:
        """格式化IoC信息"""
        content = f"IoC指标信息:\n"
        
        ioc = ioc_info.get('ioc', {})
        content += f"值: {ioc.get('value', '')}\n"
        content += f"类型: {ioc.get('type', '')}\n"
        content += f"置信度: {ioc.get('confidence', 0)}\n"
        
        malware_families = ioc_info.get('malware_families', [])
        if malware_families:
            content += f"关联恶意软件: {', '.join([m.get('name', '') for m in malware_families])}\n"
        
        apt_groups = ioc_info.get('apt_groups', [])
        if apt_groups:
            content += f"关联APT组织: {', '.join([a.get('name', '') for a in apt_groups])}\n"
        
        return content
    
    def _format_apt_info(self, apt_info: Dict[str, Any]) -> str:
        """格式化APT信息"""
        content = f"APT组织活动信息:\n"
        
        apt_group = apt_info.get('apt_group', {})
        content += f"组织名称: {apt_group.get('name', '')}\n"
        content += f"起源: {apt_group.get('origin', '')}\n"
        content += f"动机: {apt_group.get('motivation', '')}\n"
        
        malware_tools = apt_info.get('malware_tools', [])
        if malware_tools:
            content += f"使用的恶意软件: {', '.join([m.get('name', '') for m in malware_tools])}\n"
        
        techniques = apt_info.get('techniques', [])
        if techniques:
            content += f"攻击技术: {', '.join([t.get('name', '') for t in techniques])}\n"
        
        return content
    
    def _format_related_entities(self, entities: List[Dict[str, Any]]) -> str:
        """格式化相关实体信息"""
        content = "相关实体信息:\n"
        
        for entity in entities[:5]:  # 限制显示数量
            labels = entity.get('entity_labels', [])
            if 'IoC' in labels:
                content += f"- IoC: {entity.get('value', '')}\n"
            elif 'APTGroup' in labels:
                content += f"- APT组织: {entity.get('name', '')}\n"
            elif 'Technique' in labels:
                content += f"- 攻击技术: {entity.get('name', '')} ({entity.get('mitre_id', '')})\n"
            elif 'Vulnerability' in labels:
                content += f"- 漏洞: {entity.get('cve_id', '')}\n"
        
        return content
    
    def _format_attack_pattern(self, pattern: Dict[str, Any]) -> str:
        """格式化攻击模式"""
        content = "攻击模式信息:\n"
        
        apt = pattern.get('apt', {})
        malware = pattern.get('malware', {})
        technique = pattern.get('technique', {})
        
        content += f"APT组织: {apt.get('name', '')}\n"
        content += f"恶意软件: {malware.get('name', '')}\n"
        content += f"攻击技术: {technique.get('name', '')} ({technique.get('mitre_id', '')})\n"
        
        vulnerabilities = pattern.get('vulnerabilities', [])
        if vulnerabilities:
            content += f"利用漏洞: {', '.join([v.get('cve_id', '') for v in vulnerabilities])}\n"
        
        return content
    
    def _merge_results(
        self,
        vector_results: List[Dict[str, Any]],
        graph_results: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """融合向量和图谱检索结果"""
        merged = []
        
        # 添加向量结果（调整权重）
        for result in vector_results:
            result['final_score'] = result['retrieval_score'] * self.vector_weight
            merged.append(result)
        
        # 添加图谱结果（调整权重）
        for result in graph_results:
            result['final_score'] = result['retrieval_score'] * self.graph_weight
            merged.append(result)
        
        return merged
    
    def _expand_with_graph(self, results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """使用知识图谱扩展检索结果"""
        expanded = []
        
        try:
            for result in results[:3]:  # 只对前几个结果进行扩展
                metadata = result.get('metadata', {})
                source = metadata.get('source', '')
                
                if source and self.graph_query:
                    # 查找与文档相关的实体
                    doc_entities = self.graph_query.neo4j.find_nodes(
                        label='Document',
                        properties={'source': source},
                        limit=5
                    )
                    
                    for doc_entity in doc_entities:
                        # 查找文档包含的威胁实体
                        related_query = """
                        MATCH (doc:Document {chunk_id: $chunk_id})-[:CONTAINS]->(entity)
                        RETURN entity, labels(entity) as entity_labels
                        LIMIT 5
                        """
                        
                        related_entities = self.graph_query.neo4j.run_query(
                            related_query,
                            {'chunk_id': doc_entity.get('chunk_id', '')}
                        )
                        
                        if related_entities:
                            expanded_content = self._format_related_entities(related_entities)
                            expanded.append({
                                'content': expanded_content,
                                'metadata': {'source': source, 'expanded': True},
                                'retrieval_source': 'graph_expansion',
                                'final_score': 0.3
                            })
                            
        except Exception as e:
            logger.error(f"图谱扩展失败: {str(e)}")
        
        return expanded
    
    def _rerank_and_deduplicate(
        self,
        results: List[Dict[str, Any]],
        query: str
    ) -> List[Dict[str, Any]]:
        """重排序和去重"""
        # 去重（基于内容相似性）
        unique_results = []
        seen_contents = set()
        
        for result in results:
            content = result.get('content', '')
            content_hash = hash(content[:200])  # 使用前200字符的哈希值去重
            
            if content_hash not in seen_contents:
                seen_contents.add(content_hash)
                unique_results.append(result)
        
        # 按final_score排序
        unique_results.sort(key=lambda x: x.get('final_score', 0), reverse=True)
        
        return unique_results
    
    def _build_filter_expr(self, filters: Dict[str, Any] = None) -> Optional[str]:
        """构建过滤表达式"""
        if not filters:
            return None
        
        conditions = []
        
        for key, value in filters.items():
            if isinstance(value, str):
                conditions.append(f'{key} == "{value}"')
            elif isinstance(value, (int, float)):
                conditions.append(f'{key} == {value}')
            elif isinstance(value, list):
                value_conditions = [
                    f'{key} == "{v}"' if isinstance(v, str) else f'{key} == {v}'
                    for v in value
                ]
                conditions.append(f"({' or '.join(value_conditions)})")
        
        return ' and '.join(conditions) if conditions else None 