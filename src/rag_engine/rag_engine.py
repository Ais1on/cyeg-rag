"""
威胁情报RAG引擎 - 整合所有组件的核心引擎
"""
from typing import List, Dict, Any, Optional
from loguru import logger
from .retriever import HybridRetriever
from .generator import ResponseGenerator
from ..document_processor.processor import ThreatIntelProcessor
from ..vector_store.milvus_store import MilvusVectorStore
from ..vector_store.embedder import EmbeddingGenerator
from ..knowledge_graph.graph_builder import ThreatIntelGraphBuilder
from ..knowledge_graph.graph_query import GraphQueryEngine
from ..llm.deepseek_client import DeepSeekClient
from ..utils.config import get_settings


class ThreatIntelRAGEngine:
    """威胁情报RAG引擎"""
    
    def __init__(
        self,
        processor: ThreatIntelProcessor = None,
        retriever: HybridRetriever = None,
        generator: ResponseGenerator = None,
        graph_builder: ThreatIntelGraphBuilder = None,
        auto_init: bool = True
    ):
        """
        初始化RAG引擎
        
        Args:
            processor: 威胁情报处理器
            retriever: 混合检索器
            generator: 响应生成器
            graph_builder: 知识图谱构建器
            auto_init: 是否自动初始化所有组件
        """
        self.settings = get_settings()
        
        # 初始化基础组件
        if auto_init:
            self._init_components()
        
        # 设置自定义组件
        self.processor = processor or self.processor
        self.retriever = retriever or self.retriever
        self.generator = generator or self.generator
        self.graph_builder = graph_builder or self.graph_builder
        
        logger.info("威胁情报RAG引擎初始化完成")
    
    def _init_components(self):
        """初始化所有组件"""
        try:
            # 1. 初始化嵌入生成器
            self.embedder = EmbeddingGenerator(
                model_name=self.settings.embedding_model,
                model_type="auto"
            )
            
            # 2. 初始化向量存储
            self.vector_store = MilvusVectorStore(
                collection_name="threat_intel_rag",
                embedding_dim=self.embedder.get_embedding_dim(),
                auto_create=True
            )
            
            # 3. 初始化知识图谱组件
            self.graph_query = GraphQueryEngine()
            self.graph_builder = ThreatIntelGraphBuilder()
            
            # 4. 初始化LLM客户端
            self.llm_client = DeepSeekClient(
                api_key=self.settings.deepseek_api_key,
                base_url=self.settings.deepseek_base_url
            )
            
            # 5. 初始化文档处理器
            self.processor = ThreatIntelProcessor(
                embedding_model=self.settings.embedding_model,
                vector_store_config={
                    'collection_name': 'threat_intel_rag',
                    'embedding_dim': self.embedder.get_embedding_dim()
                }
            )
            
            # 6. 初始化检索器
            self.retriever = HybridRetriever(
                vector_store=self.vector_store,
                embedder=self.embedder,
                graph_query=self.graph_query
            )
            
            # 7. 初始化响应生成器
            self.generator = ResponseGenerator(
                llm_client=self.llm_client
            )
            
            logger.info("所有RAG组件初始化成功")
            
        except Exception as e:
            logger.error(f"初始化RAG组件失败: {str(e)}")
            raise
    
    def ingest_documents(
        self,
        source: str,
        source_type: str = "directory",
        build_knowledge_graph: bool = True,
        return_stats: bool = True
    ) -> Dict[str, Any]:
        """
        文档摄取和处理
        
        Args:
            source: 文档源
            source_type: 源类型
            build_knowledge_graph: 是否构建知识图谱
            return_stats: 是否返回统计信息
            
        Returns:
            摄取结果和统计信息
        """
        try:
            logger.info(f"开始摄取文档: {source}")
            
            # 1. 处理文档
            result = self.processor.process_documents(
                source=source,
                source_type=source_type,
                store_vectors=True,
                return_chunks=build_knowledge_graph
            )
            
            # 2. 构建知识图谱（可选）
            if build_knowledge_graph and result.get('chunks'):
                logger.info("开始构建知识图谱...")
                graph_stats = self.graph_builder.build_graph_from_documents(
                    chunks=result['chunks'],
                    extract_entities=True
                )
                result['graph_stats'] = graph_stats
            
            logger.info(f"文档摄取完成: {result.get('stats', {})}")
            
            return result if return_stats else {'status': 'success'}
            
        except Exception as e:
            logger.error(f"文档摄取失败: {str(e)}")
            return {'status': 'error', 'error': str(e)}
    
    def query(
        self,
        question: str,
        retrieval_method: str = "hybrid",
        response_type: str = "comprehensive",
        top_k: int = 10,
        include_sources: bool = True,
        filters: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """
        执行RAG查询
        
        Args:
            question: 用户问题
            retrieval_method: 检索方法 ("vector", "graph", "hybrid")
            response_type: 响应类型 ("brief", "comprehensive", "analytical")
            top_k: 检索结果数量
            include_sources: 是否包含来源信息
            filters: 过滤条件
            
        Returns:
            查询结果
        """
        try:
            logger.info(f"执行RAG查询: {question}")
            
            # 1. 检索相关内容
            retrieved_contexts = self.retriever.retrieve(
                query=question,
                top_k=top_k,
                retrieval_method=retrieval_method,
                filters=filters,
                expand_with_graph=True
            )
            
            logger.info(f"检索到 {len(retrieved_contexts)} 个相关上下文")
            
            # 2. 生成响应
            response_result = self.generator.generate_response(
                query=question,
                retrieved_contexts=retrieved_contexts,
                response_type=response_type,
                include_sources=include_sources
            )
            
            # 3. 添加检索统计信息
            response_result['retrieval_stats'] = {
                'total_retrieved': len(retrieved_contexts),
                'retrieval_method': retrieval_method,
                'top_k': top_k
            }
            
            return response_result
            
        except Exception as e:
            logger.error(f"RAG查询失败: {str(e)}")
            return {
                'response': '查询失败，请稍后重试。',
                'error': str(e)
            }
    
    def analyze_threat(
        self,
        query: str,
        context_sources: List[str] = None,
        include_graph_analysis: bool = True
    ) -> Dict[str, Any]:
        """
        威胁分析
        
        Args:
            query: 分析请求
            context_sources: 指定的上下文源
            include_graph_analysis: 是否包含图谱分析
            
        Returns:
            威胁分析结果
        """
        try:
            logger.info(f"执行威胁分析: {query}")
            
            # 1. 检索相关威胁情报
            filters = {}
            if context_sources:
                filters['source'] = context_sources
            
            retrieved_contexts = self.retriever.retrieve(
                query=query,
                top_k=15,
                retrieval_method="hybrid",
                filters=filters,
                expand_with_graph=include_graph_analysis
            )
            
            # 2. 生成威胁分析报告
            analysis_result = self.generator.generate_threat_analysis(
                query=query,
                retrieved_contexts=retrieved_contexts
            )
            
            # 3. 添加图谱分析（如果启用）
            if include_graph_analysis:
                graph_analysis = self._perform_graph_analysis(query, retrieved_contexts)
                analysis_result['graph_analysis'] = graph_analysis
            
            return analysis_result
            
        except Exception as e:
            logger.error(f"威胁分析失败: {str(e)}")
            return {'error': str(e)}
    
    def analyze_ioc(
        self,
        ioc_value: str,
        ioc_type: str = "auto"
    ) -> Dict[str, Any]:
        """
        IoC分析
        
        Args:
            ioc_value: IoC值
            ioc_type: IoC类型
            
        Returns:
            IoC分析结果
        """
        try:
            logger.info(f"执行IoC分析: {ioc_value}")
            
            # 1. 从知识图谱查询IoC关联信息
            ioc_associations = self.graph_query.find_ioc_associations(ioc_value)
            
            # 2. 向量检索相关文档
            retrieved_contexts = self.retriever.retrieve(
                query=f"IoC {ioc_value}",
                top_k=10,
                retrieval_method="hybrid"
            )
            
            # 3. 合并知识图谱和向量检索结果
            if ioc_associations:
                graph_context = {
                    'content': self._format_ioc_associations(ioc_associations),
                    'metadata': {'source': 'knowledge_graph'},
                    'retrieval_source': 'graph',
                    'retrieval_score': 0.9
                }
                retrieved_contexts.insert(0, graph_context)
            
            # 4. 生成IoC分析报告
            ioc_report = self.generator.generate_ioc_report(
                ioc_value=ioc_value,
                retrieved_contexts=retrieved_contexts
            )
            
            # 5. 添加关联分析
            ioc_report['associations'] = ioc_associations
            
            return ioc_report
            
        except Exception as e:
            logger.error(f"IoC分析失败: {str(e)}")
            return {'error': str(e)}
    
    def search_similar_threats(
        self,
        reference_threat: str,
        similarity_threshold: float = 0.5,
        max_results: int = 20
    ) -> List[Dict[str, Any]]:
        """
        搜索相似威胁
        
        Args:
            reference_threat: 参考威胁描述
            similarity_threshold: 相似度阈值
            max_results: 最大结果数
            
        Returns:
            相似威胁列表
        """
        try:
            # 使用向量检索找相似威胁
            similar_threats = self.retriever.retrieve(
                query=reference_threat,
                top_k=max_results,
                retrieval_method="vector"
            )
            
            # 过滤相似度
            filtered_threats = [
                threat for threat in similar_threats
                if threat.get('retrieval_score', 0) >= similarity_threshold
            ]
            
            return filtered_threats
            
        except Exception as e:
            logger.error(f"搜索相似威胁失败: {str(e)}")
            return []
    
    def get_threat_landscape(self, time_range: str = "last_30_days") -> Dict[str, Any]:
        """
        获取威胁态势
        
        Args:
            time_range: 时间范围
            
        Returns:
            威胁态势分析
        """
        try:
            # 从知识图谱获取威胁态势
            landscape = self.graph_query.analyze_threat_landscape(time_range)
            
            # 添加趋势分析
            trends = self._analyze_threat_trends(landscape)
            landscape['trends'] = trends
            
            return landscape
            
        except Exception as e:
            logger.error(f"获取威胁态势失败: {str(e)}")
            return {'error': str(e)}
    
    def natural_language_query(self, question: str) -> str:
        """
        自然语言图谱查询
        
        Args:
            question: 自然语言问题
            
        Returns:
            自然语言回答
        """
        try:
            return self.graph_query.natural_language_query(question)
        except Exception as e:
            logger.error(f"自然语言查询失败: {str(e)}")
            return "查询失败，请稍后重试。"
    
    def get_system_status(self) -> Dict[str, Any]:
        """
        获取系统状态
        
        Returns:
            系统状态信息
        """
        try:
            status = {
                'vector_store': self.vector_store.get_stats(),
                'knowledge_graph': self.graph_builder.get_graph_statistics(),
                'embedder': {
                    'model': self.embedder.model_name,
                    'dimension': self.embedder.get_embedding_dim()
                },
                'llm': {
                    'model': self.llm_client.model_name
                }
            }
            
            return status
            
        except Exception as e:
            logger.error(f"获取系统状态失败: {str(e)}")
            return {'error': str(e)}
    
    def clear_data(self, confirm: bool = False):
        """
        清空所有数据（谨慎使用）
        
        Args:
            confirm: 确认标志
        """
        if not confirm:
            logger.warning("清空数据需要确认，请设置confirm=True")
            return
        
        try:
            # 清空向量数据库
            self.vector_store.drop_collection()
            
            # 清空知识图谱
            self.graph_builder.neo4j.clear_database()
            
            logger.info("所有数据已清空")
            
        except Exception as e:
            logger.error(f"清空数据失败: {str(e)}")
            raise
    
    def _perform_graph_analysis(
        self,
        query: str,
        contexts: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """执行图谱分析"""
        try:
            # 提取查询中的实体
            entities = self._extract_entities_from_query(query)
            
            graph_analysis = {
                'entities_found': entities,
                'relationships': [],
                'attack_patterns': []
            }
            
            # 分析实体关系
            for entity_type, entity_values in entities.items():
                for entity_value in entity_values:
                    if entity_type == "ioc":
                        # 查找IoC关联
                        associations = self.graph_query.find_ioc_associations(entity_value)
                        if associations:
                            graph_analysis['relationships'].append({
                                'entity': entity_value,
                                'type': 'ioc',
                                'associations': associations
                            })
                    
                    elif entity_type == "apt":
                        # 查找APT活动
                        campaigns = self.graph_query.find_apt_campaigns(entity_value)
                        if campaigns:
                            graph_analysis['attack_patterns'].append({
                                'apt_group': entity_value,
                                'campaigns': campaigns
                            })
            
            return graph_analysis
            
        except Exception as e:
            logger.error(f"图谱分析失败: {str(e)}")
            return {}
    
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
        
        return entities
    
    def _format_ioc_associations(self, associations: Dict[str, Any]) -> str:
        """格式化IoC关联信息"""
        content = "IoC关联分析:\n"
        
        ioc = associations.get('ioc', {})
        content += f"IoC值: {ioc.get('value', '')}\n"
        content += f"类型: {ioc.get('type', '')}\n"
        
        malware_families = associations.get('malware_families', [])
        if malware_families:
            content += f"关联恶意软件: {', '.join([m.get('name', '') for m in malware_families])}\n"
        
        apt_groups = associations.get('apt_groups', [])
        if apt_groups:
            content += f"关联APT组织: {', '.join([a.get('name', '') for a in apt_groups])}\n"
        
        return content
    
    def _analyze_threat_trends(self, landscape: Dict[str, Any]) -> Dict[str, Any]:
        """分析威胁趋势"""
        trends = {
            'rising_threats': [],
            'declining_threats': [],
            'new_techniques': [],
            'active_campaigns': []
        }
        
        # 基于威胁态势数据分析趋势
        top_threats = landscape.get('top_threats', [])
        if top_threats:
            # 简单的趋势分析逻辑
            trends['rising_threats'] = top_threats[:3]
        
        return trends
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        # 清理资源
        try:
            if hasattr(self, 'vector_store'):
                # Milvus连接会自动清理
                pass
            
            if hasattr(self, 'graph_builder') and self.graph_builder:
                self.graph_builder.neo4j.close()
            
            if hasattr(self, 'llm_client') and self.llm_client:
                del self.llm_client
                
        except Exception as e:
            logger.error(f"清理资源时出错: {str(e)}") 