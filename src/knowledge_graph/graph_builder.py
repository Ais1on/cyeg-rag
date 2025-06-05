"""
威胁情报知识图谱构建器
"""
from typing import List, Dict, Any, Optional
from loguru import logger
from .neo4j_client import Neo4jClient
from ..llm.deepseek_client import DeepSeekClient
from ..document_processor.chunker import DocumentChunk
from ..utils.config import get_settings


class ThreatIntelGraphBuilder:
    """威胁情报知识图谱构建器"""
    
    def __init__(self, neo4j_client: Neo4jClient = None, llm_client: DeepSeekClient = None):
        """
        初始化图构建器
        
        Args:
            neo4j_client: Neo4j客户端
            llm_client: LLM客户端
        """
        self.settings = get_settings()
        self.neo4j = neo4j_client or Neo4jClient()
        self.llm = llm_client or DeepSeekClient(
            api_key=self.settings.deepseek_api_key,
            base_url=self.settings.deepseek_base_url
        )
        
        # 威胁情报节点类型
        self.node_types = {
            'IOC': 'IoC',
            'MALWARE': 'Malware',
            'APT_GROUP': 'APTGroup', 
            'VULNERABILITY': 'Vulnerability',
            'TECHNIQUE': 'Technique',
            'CAMPAIGN': 'Campaign',
            'DOCUMENT': 'Document',
            'ORGANIZATION': 'Organization',
            'LOCATION': 'Location'
        }
        
        # 关系类型
        self.relationship_types = {
            'USES': 'USES',
            'TARGETS': 'TARGETS',
            'EXPLOITS': 'EXPLOITS',
            'ATTRIBUTED_TO': 'ATTRIBUTED_TO',
            'RELATED_TO': 'RELATED_TO',
            'CONTAINS': 'CONTAINS',
            'COMMUNICATES_WITH': 'COMMUNICATES_WITH',
            'DOWNLOADS': 'DOWNLOADS',
            'LOCATED_IN': 'LOCATED_IN'
        }
        
        self._create_constraints()
    
    def _create_constraints(self):
        """创建数据库约束"""
        try:
            constraints = [
                "CREATE CONSTRAINT ioc_value IF NOT EXISTS FOR (i:IoC) REQUIRE i.value IS UNIQUE",
                "CREATE CONSTRAINT malware_name IF NOT EXISTS FOR (m:Malware) REQUIRE m.name IS UNIQUE",
                "CREATE CONSTRAINT apt_name IF NOT EXISTS FOR (a:APTGroup) REQUIRE a.name IS UNIQUE",
                "CREATE CONSTRAINT vuln_id IF NOT EXISTS FOR (v:Vulnerability) REQUIRE v.cve_id IS UNIQUE",
                "CREATE CONSTRAINT technique_id IF NOT EXISTS FOR (t:Technique) REQUIRE t.mitre_id IS UNIQUE"
            ]
            
            for constraint in constraints:
                try:
                    self.neo4j.run_query(constraint)
                except Exception:
                    # 约束可能已存在，忽略错误
                    pass
                    
            logger.info("数据库约束创建完成")
            
        except Exception as e:
            logger.warning(f"创建数据库约束时出现警告: {str(e)}")
    
    def build_graph_from_documents(
        self,
        chunks: List[DocumentChunk],
        extract_entities: bool = True
    ) -> Dict[str, Any]:
        """
        从文档分块构建知识图谱
        
        Args:
            chunks: 文档分块列表
            extract_entities: 是否使用LLM提取实体
            
        Returns:
            构建统计信息
        """
        stats = {
            'total_chunks': len(chunks),
            'processed_chunks': 0,
            'created_nodes': 0,
            'created_relationships': 0,
            'errors': []
        }
        
        logger.info(f"开始构建知识图谱，处理 {len(chunks)} 个文档分块")
        
        for chunk in chunks:
            try:
                # 创建文档节点
                doc_node = self._create_document_node(chunk)
                if doc_node:
                    stats['created_nodes'] += 1
                
                # 提取并创建实体节点
                if extract_entities:
                    entities = self._extract_entities_with_llm(chunk.content)
                else:
                    entities = chunk.metadata.get('threat_entities', {})
                
                # 处理实体
                entity_nodes = self._process_entities(entities, chunk)
                stats['created_nodes'] += len(entity_nodes)
                
                # 创建实体与文档的关系
                for entity_node in entity_nodes:
                    rel = self.neo4j.create_relationship(
                        from_node=doc_node,
                        to_node=entity_node,
                        relationship_type=self.relationship_types['CONTAINS']
                    )
                    if rel:
                        stats['created_relationships'] += 1
                
                # 创建实体间关系
                entity_rels = self._create_entity_relationships(entity_nodes, chunk.content)
                stats['created_relationships'] += len(entity_rels)
                
                stats['processed_chunks'] += 1
                
            except Exception as e:
                error_msg = f"处理分块失败 {chunk.chunk_id}: {str(e)}"
                logger.error(error_msg)
                stats['errors'].append(error_msg)
        
        logger.info(f"知识图谱构建完成: {stats}")
        return stats
    
    def _create_document_node(self, chunk: DocumentChunk) -> Dict[str, Any]:
        """创建文档节点"""
        try:
            properties = {
                'chunk_id': chunk.chunk_id,
                'source': chunk.metadata.get('source', ''),
                'content': chunk.content[:1000],  # 限制内容长度
                'chunk_index': chunk.metadata.get('chunk_index', 0),
                'file_type': chunk.metadata.get('file_type', ''),
                'created_at': chunk.metadata.get('created_at', '')
            }
            
            return self.neo4j.create_node('Document', properties)
            
        except Exception as e:
            logger.error(f"创建文档节点失败: {str(e)}")
            return None
    
    def _extract_entities_with_llm(self, text: str) -> Dict[str, List[Dict]]:
        """使用LLM提取威胁情报实体"""
        try:
            return self.llm.extract_threat_entities_advanced(text)
        except Exception as e:
            logger.error(f"LLM实体提取失败: {str(e)}")
            return {}
    
    def _process_entities(
        self,
        entities: Dict[str, List[Dict]],
        chunk: DocumentChunk
    ) -> List[Dict[str, Any]]:
        """处理并创建实体节点"""
        entity_nodes = []
        
        try:
            # 处理IoC指标
            for ioc in entities.get('ioc', []):
                node = self._create_ioc_node(ioc)
                if node:
                    entity_nodes.append({**node, 'label': 'IoC'})
            
            # 处理恶意软件
            for malware in entities.get('malware', []):
                node = self._create_malware_node(malware)
                if node:
                    entity_nodes.append({**node, 'label': 'Malware'})
            
            # 处理APT组织
            for apt in entities.get('apt_groups', []):
                node = self._create_apt_node(apt)
                if node:
                    entity_nodes.append({**node, 'label': 'APTGroup'})
            
            # 处理漏洞
            for vuln in entities.get('cve', []):
                node = self._create_vulnerability_node(vuln)
                if node:
                    entity_nodes.append({**node, 'label': 'Vulnerability'})
            
            # 处理技术
            for technique in entities.get('techniques', []):
                node = self._create_technique_node(technique)
                if node:
                    entity_nodes.append({**node, 'label': 'Technique'})
            
            # 处理位置
            for location in entities.get('locations', []):
                node = self._create_location_node(location)
                if node:
                    entity_nodes.append({**node, 'label': 'Location'})
                    
        except Exception as e:
            logger.error(f"处理实体失败: {str(e)}")
        
        return entity_nodes
    
    def _create_ioc_node(self, ioc: Dict[str, Any]) -> Optional[Dict]:
        """创建IoC节点"""
        try:
            properties = {
                'value': ioc.get('value', ''),
                'type': ioc.get('type', ''),
                'confidence': ioc.get('confidence', 0.0),
                'context': ioc.get('context', ''),
                'first_seen': ioc.get('first_seen', ''),
                'last_seen': ioc.get('last_seen', ''),
                'threat_type': ioc.get('threat_type', '')
            }
            
            return self.neo4j.create_node('IoC', properties)
            
        except Exception as e:
            logger.error(f"创建IoC节点失败: {str(e)}")
            return None
    
    def _create_malware_node(self, malware: Dict[str, Any]) -> Optional[Dict]:
        """创建恶意软件节点"""
        try:
            properties = {
                'name': malware.get('name', ''),
                'family': malware.get('family', ''),
                'type': malware.get('type', ''),
                'description': malware.get('description', ''),
                'capabilities': malware.get('capabilities', []),
                'platforms': malware.get('platforms', [])
            }
            
            return self.neo4j.create_node('Malware', properties)
            
        except Exception as e:
            logger.error(f"创建恶意软件节点失败: {str(e)}")
            return None
    
    def _create_apt_node(self, apt: Dict[str, Any]) -> Optional[Dict]:
        """创建APT组织节点"""
        try:
            properties = {
                'name': apt.get('name', ''),
                'aliases': apt.get('aliases', []),
                'origin': apt.get('origin', ''),
                'motivation': apt.get('motivation', ''),
                'targets': apt.get('targets', []),
                'active_since': apt.get('active_since', ''),
                'description': apt.get('description', '')
            }
            
            return self.neo4j.create_node('APTGroup', properties)
            
        except Exception as e:
            logger.error(f"创建APT组织节点失败: {str(e)}")
            return None
    
    def _create_vulnerability_node(self, vuln: Dict[str, Any]) -> Optional[Dict]:
        """创建漏洞节点"""
        try:
            properties = {
                'cve_id': vuln.get('value', ''),
                'severity': vuln.get('severity', ''),
                'score': vuln.get('score', 0.0),
                'description': vuln.get('description', ''),
                'published_date': vuln.get('published_date', ''),
                'modified_date': vuln.get('modified_date', ''),
                'affected_products': vuln.get('affected_products', [])
            }
            
            return self.neo4j.create_node('Vulnerability', properties)
            
        except Exception as e:
            logger.error(f"创建漏洞节点失败: {str(e)}")
            return None
    
    def _create_technique_node(self, technique: Dict[str, Any]) -> Optional[Dict]:
        """创建攻击技术节点"""
        try:
            properties = {
                'mitre_id': technique.get('id', ''),
                'name': technique.get('name', ''),
                'tactic': technique.get('tactic', ''),
                'description': technique.get('description', ''),
                'platforms': technique.get('platforms', []),
                'data_sources': technique.get('data_sources', [])
            }
            
            return self.neo4j.create_node('Technique', properties)
            
        except Exception as e:
            logger.error(f"创建攻击技术节点失败: {str(e)}")
            return None
    
    def _create_location_node(self, location: Dict[str, Any]) -> Optional[Dict]:
        """创建位置节点"""
        try:
            properties = {
                'name': location.get('name', ''),
                'country': location.get('country', ''),
                'region': location.get('region', ''),
                'coordinates': location.get('coordinates', ''),
                'type': location.get('type', '')
            }
            
            return self.neo4j.create_node('Location', properties)
            
        except Exception as e:
            logger.error(f"创建位置节点失败: {str(e)}")
            return None
    
    def _create_entity_relationships(
        self,
        entity_nodes: List[Dict[str, Any]],
        context: str
    ) -> List[Dict]:
        """创建实体间关系"""
        relationships = []
        
        try:
            # 基于上下文和实体类型创建关系
            for i, entity1 in enumerate(entity_nodes):
                for entity2 in entity_nodes[i+1:]:
                    rel_type = self._determine_relationship_type(entity1, entity2, context)
                    if rel_type:
                        rel = self.neo4j.create_relationship(
                            from_node=entity1,
                            to_node=entity2,
                            relationship_type=rel_type,
                            properties={'context': context[:200]}
                        )
                        if rel:
                            relationships.append(rel)
                            
        except Exception as e:
            logger.error(f"创建实体关系失败: {str(e)}")
        
        return relationships
    
    def _determine_relationship_type(
        self,
        entity1: Dict[str, Any],
        entity2: Dict[str, Any],
        context: str
    ) -> Optional[str]:
        """确定实体间关系类型"""
        label1 = entity1.get('label', '')
        label2 = entity2.get('label', '')
        
        # 定义关系规则
        relationship_rules = {
            ('APTGroup', 'Malware'): 'USES',
            ('APTGroup', 'Technique'): 'USES',
            ('APTGroup', 'Vulnerability'): 'EXPLOITS',
            ('APTGroup', 'Organization'): 'TARGETS',
            ('APTGroup', 'Location'): 'LOCATED_IN',
            ('Malware', 'IoC'): 'COMMUNICATES_WITH',
            ('Malware', 'Technique'): 'USES',
            ('Malware', 'Vulnerability'): 'EXPLOITS',
            ('IoC', 'IoC'): 'RELATED_TO'
        }
        
        # 检查正向关系
        rel_type = relationship_rules.get((label1, label2))
        if rel_type:
            return rel_type
        
        # 检查反向关系
        rel_type = relationship_rules.get((label2, label1))
        if rel_type:
            return rel_type
        
        # 默认关系
        return 'RELATED_TO'
    
    def enrich_graph_with_external_data(self, source: str = "mitre"):
        """使用外部数据丰富知识图谱"""
        try:
            if source == "mitre":
                self._enrich_with_mitre_data()
            elif source == "cve":
                self._enrich_with_cve_data()
                
        except Exception as e:
            logger.error(f"使用外部数据丰富图谱失败: {str(e)}")
    
    def _enrich_with_mitre_data(self):
        """使用MITRE ATT&CK数据丰富图谱"""
        # 这里可以集成MITRE ATT&CK的API或数据文件
        logger.info("MITRE数据丰富功能待实现")
    
    def _enrich_with_cve_data(self):
        """使用CVE数据丰富图谱"""
        # 这里可以集成CVE数据库的API
        logger.info("CVE数据丰富功能待实现")
    
    def get_graph_statistics(self) -> Dict[str, Any]:
        """获取图谱统计信息"""
        return self.neo4j.get_graph_stats() 