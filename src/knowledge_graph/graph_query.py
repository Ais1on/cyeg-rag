"""
知识图谱查询引擎
"""
from typing import List, Dict, Any, Optional
from loguru import logger
from .neo4j_client import Neo4jClient
from ..llm.deepseek_client import DeepSeekClient
from ..utils.config import get_settings


class GraphQueryEngine:
    """知识图谱查询引擎"""
    
    def __init__(self, neo4j_client: Neo4jClient = None, llm_client: DeepSeekClient = None):
        """
        初始化查询引擎
        
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
    
    def find_related_entities(
        self,
        entity_type: str,
        entity_value: str,
        max_depth: int = 2,
        limit: int = 20
    ) -> List[Dict[str, Any]]:
        """
        查找相关实体
        
        Args:
            entity_type: 实体类型
            entity_value: 实体值
            max_depth: 最大查询深度
            limit: 结果数量限制
            
        Returns:
            相关实体列表
        """
        try:
            if entity_type == "IoC":
                query = f"""
                MATCH (start:IoC {{value: $value}})
                MATCH path = (start)-[*1..{max_depth}]-(related)
                WHERE related <> start
                RETURN DISTINCT related, labels(related) as labels, 
                       length(path) as distance
                ORDER BY distance
                LIMIT {limit}
                """
            elif entity_type == "Malware":
                query = f"""
                MATCH (start:Malware {{name: $value}})
                MATCH path = (start)-[*1..{max_depth}]-(related)
                WHERE related <> start
                RETURN DISTINCT related, labels(related) as labels,
                       length(path) as distance
                ORDER BY distance
                LIMIT {limit}
                """
            elif entity_type == "APTGroup":
                query = f"""
                MATCH (start:APTGroup {{name: $value}})
                MATCH path = (start)-[*1..{max_depth}]-(related)
                WHERE related <> start
                RETURN DISTINCT related, labels(related) as labels,
                       length(path) as distance
                ORDER BY distance
                LIMIT {limit}
                """
            else:
                query = f"""
                MATCH (start {{name: $value}})
                MATCH path = (start)-[*1..{max_depth}]-(related)
                WHERE related <> start
                RETURN DISTINCT related, labels(related) as labels,
                       length(path) as distance
                ORDER BY distance
                LIMIT {limit}
                """
            
            results = self.neo4j.run_query(query, {"value": entity_value})
            
            formatted_results = []
            for result in results:
                entity = result['related']
                entity['entity_labels'] = result['labels']
                entity['distance'] = result['distance']
                formatted_results.append(entity)
            
            return formatted_results
            
        except Exception as e:
            logger.error(f"查找相关实体失败: {str(e)}")
            return []
    
    def find_attack_patterns(
        self,
        apt_group: str = None,
        malware: str = None,
        technique: str = None
    ) -> List[Dict[str, Any]]:
        """
        查找攻击模式
        
        Args:
            apt_group: APT组织名称
            malware: 恶意软件名称
            technique: 攻击技术
            
        Returns:
            攻击模式列表
        """
        try:
            conditions = []
            params = {}
            
            if apt_group:
                conditions.append("apt.name = $apt_name")
                params["apt_name"] = apt_group
            
            if malware:
                conditions.append("malware.name = $malware_name")
                params["malware_name"] = malware
            
            if technique:
                conditions.append("technique.mitre_id = $technique_id OR technique.name = $technique_name")
                params["technique_id"] = technique
                params["technique_name"] = technique
            
            where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""
            
            query = f"""
            MATCH (apt:APTGroup)-[:USES]->(malware:Malware)-[:USES]->(technique:Technique)
            {where_clause}
            OPTIONAL MATCH (malware)-[:EXPLOITS]->(vuln:Vulnerability)
            OPTIONAL MATCH (malware)-[:COMMUNICATES_WITH]->(ioc:IoC)
            RETURN apt, malware, technique, 
                   collect(DISTINCT vuln) as vulnerabilities,
                   collect(DISTINCT ioc) as iocs
            LIMIT 20
            """
            
            return self.neo4j.run_query(query, params)
            
        except Exception as e:
            logger.error(f"查找攻击模式失败: {str(e)}")
            return []
    
    def find_ioc_associations(self, ioc_value: str) -> Dict[str, Any]:
        """
        查找IoC关联信息
        
        Args:
            ioc_value: IoC值
            
        Returns:
            IoC关联信息
        """
        try:
            query = """
            MATCH (ioc:IoC {value: $ioc_value})
            OPTIONAL MATCH (ioc)-[:RELATED_TO]-(related_ioc:IoC)
            OPTIONAL MATCH (malware:Malware)-[:COMMUNICATES_WITH]-(ioc)
            OPTIONAL MATCH (apt:APTGroup)-[:USES]->(malware)
            OPTIONAL MATCH (doc:Document)-[:CONTAINS]->(ioc)
            RETURN ioc,
                   collect(DISTINCT related_ioc) as related_iocs,
                   collect(DISTINCT malware) as malware_families,
                   collect(DISTINCT apt) as apt_groups,
                   collect(DISTINCT doc) as documents
            """
            
            results = self.neo4j.run_query(query, {"ioc_value": ioc_value})
            
            if results:
                result = results[0]
                return {
                    'ioc': result['ioc'],
                    'related_iocs': result['related_iocs'],
                    'malware_families': result['malware_families'],
                    'apt_groups': result['apt_groups'],
                    'documents': result['documents']
                }
            else:
                return {}
                
        except Exception as e:
            logger.error(f"查找IoC关联信息失败: {str(e)}")
            return {}
    
    def find_apt_campaigns(self, apt_name: str) -> Dict[str, Any]:
        """
        查找APT组织的活动情况
        
        Args:
            apt_name: APT组织名称
            
        Returns:
            APT活动信息
        """
        try:
            query = """
            MATCH (apt:APTGroup {name: $apt_name})
            OPTIONAL MATCH (apt)-[:USES]->(malware:Malware)
            OPTIONAL MATCH (apt)-[:USES]->(technique:Technique)
            OPTIONAL MATCH (apt)-[:EXPLOITS]->(vuln:Vulnerability)
            OPTIONAL MATCH (apt)-[:TARGETS]->(org:Organization)
            OPTIONAL MATCH (malware)-[:COMMUNICATES_WITH]->(ioc:IoC)
            RETURN apt,
                   collect(DISTINCT malware) as malware_tools,
                   collect(DISTINCT technique) as techniques,
                   collect(DISTINCT vuln) as vulnerabilities,
                   collect(DISTINCT org) as targets,
                   collect(DISTINCT ioc) as iocs
            """
            
            results = self.neo4j.run_query(query, {"apt_name": apt_name})
            
            if results:
                result = results[0]
                return {
                    'apt_group': result['apt'],
                    'malware_tools': result['malware_tools'],
                    'techniques': result['techniques'],
                    'vulnerabilities': result['vulnerabilities'],
                    'targets': result['targets'],
                    'iocs': result['iocs']
                }
            else:
                return {}
                
        except Exception as e:
            logger.error(f"查找APT活动失败: {str(e)}")
            return {}
    
    def analyze_threat_landscape(
        self,
        time_range: str = "last_30_days"
    ) -> Dict[str, Any]:
        """
        分析威胁态势
        
        Args:
            time_range: 时间范围
            
        Returns:
            威胁态势分析结果
        """
        try:
            # 获取各类威胁实体统计
            stats_query = """
            MATCH (ioc:IoC) WITH count(ioc) as ioc_count
            MATCH (malware:Malware) WITH ioc_count, count(malware) as malware_count
            MATCH (apt:APTGroup) WITH ioc_count, malware_count, count(apt) as apt_count
            MATCH (vuln:Vulnerability) WITH ioc_count, malware_count, apt_count, count(vuln) as vuln_count
            MATCH (technique:Technique) WITH ioc_count, malware_count, apt_count, vuln_count, count(technique) as technique_count
            RETURN ioc_count, malware_count, apt_count, vuln_count, technique_count
            """
            
            stats_result = self.neo4j.run_query(stats_query)
            
            # 获取最活跃的威胁
            top_threats_query = """
            MATCH (apt:APTGroup)-[r]-()
            WITH apt, count(r) as activity_score
            ORDER BY activity_score DESC
            LIMIT 10
            RETURN apt.name as apt_name, activity_score
            """
            
            top_threats = self.neo4j.run_query(top_threats_query)
            
            # 获取最常用的技术
            top_techniques_query = """
            MATCH (technique:Technique)<-[:USES]-()
            WITH technique, count(*) as usage_count
            ORDER BY usage_count DESC
            LIMIT 10
            RETURN technique.name as technique_name, technique.mitre_id as mitre_id, usage_count
            """
            
            top_techniques = self.neo4j.run_query(top_techniques_query)
            
            # 获取最新的IoC
            recent_iocs_query = """
            MATCH (ioc:IoC)
            WHERE ioc.first_seen IS NOT NULL
            RETURN ioc.value as ioc_value, ioc.type as ioc_type, ioc.first_seen as first_seen
            ORDER BY ioc.first_seen DESC
            LIMIT 20
            """
            
            recent_iocs = self.neo4j.run_query(recent_iocs_query)
            
            return {
                'statistics': stats_result[0] if stats_result else {},
                'top_threats': top_threats,
                'top_techniques': top_techniques,
                'recent_iocs': recent_iocs,
                'analysis_time': time_range
            }
            
        except Exception as e:
            logger.error(f"分析威胁态势失败: {str(e)}")
            return {}
    
    def natural_language_query(self, question: str) -> str:
        """
        自然语言查询
        
        Args:
            question: 自然语言问题
            
        Returns:
            查询结果的自然语言回答
        """
        try:
            # 分析问题类型并转换为Cypher查询
            cypher_query = self._generate_cypher_from_nl(question)
            
            if cypher_query:
                # 执行查询
                results = self.neo4j.run_query(cypher_query)
                
                # 使用LLM生成自然语言回答
                return self._generate_nl_answer(question, results)
            else:
                return "抱歉，无法理解您的问题。请尝试更具体的描述。"
                
        except Exception as e:
            logger.error(f"自然语言查询失败: {str(e)}")
            return "查询时发生错误，请稍后重试。"
    
    def _generate_cypher_from_nl(self, question: str) -> Optional[str]:
        """从自然语言生成Cypher查询"""
        try:
            prompt = f"""
作为威胁情报分析专家，请将以下自然语言问题转换为Neo4j Cypher查询。

知识图谱包含以下节点类型：
- IoC: IoC指标 (属性: value, type, confidence, context)
- Malware: 恶意软件 (属性: name, family, type, description)
- APTGroup: APT组织 (属性: name, aliases, origin, motivation)
- Vulnerability: 漏洞 (属性: cve_id, severity, score, description)
- Technique: 攻击技术 (属性: mitre_id, name, tactic, description)
- Document: 文档 (属性: chunk_id, source, content)

关系类型包括：USES, TARGETS, EXPLOITS, RELATED_TO, CONTAINS等。

问题：{question}

请只返回Cypher查询语句，不要包含任何解释：
"""
            
            response = self.llm.generate_text(prompt, max_tokens=500, temperature=0.1)
            
            # 简单的验证：确保返回的是Cypher查询
            if "MATCH" in response.upper() or "RETURN" in response.upper():
                return response.strip()
            else:
                return None
                
        except Exception as e:
            logger.error(f"生成Cypher查询失败: {str(e)}")
            return None
    
    def _generate_nl_answer(self, question: str, results: List[Dict]) -> str:
        """生成自然语言回答"""
        try:
            prompt = f"""
基于以下查询结果，用自然语言回答用户的问题：

用户问题：{question}

查询结果：
{results}

请提供一个准确、简洁的回答：
"""
            
            return self.llm.generate_text(prompt, max_tokens=1024, temperature=0.1)
            
        except Exception as e:
            logger.error(f"生成自然语言回答失败: {str(e)}")
            return "无法生成回答，请检查查询结果。"
    
    def find_shortest_path(
        self,
        start_entity: Dict[str, str],
        end_entity: Dict[str, str],
        max_length: int = 5
    ) -> List[Dict[str, Any]]:
        """
        查找两个实体间的最短路径
        
        Args:
            start_entity: 起始实体 {"type": "IoC", "value": "xxx"}
            end_entity: 结束实体 {"type": "Malware", "value": "xxx"}
            max_length: 最大路径长度
            
        Returns:
            路径列表
        """
        try:
            query = f"""
            MATCH (start:{start_entity['type']} {{value: $start_value}})
            MATCH (end:{end_entity['type']} {{value: $end_value}})
            MATCH path = shortestPath((start)-[*1..{max_length}]-(end))
            RETURN path, length(path) as path_length
            """
            
            params = {
                "start_value": start_entity['value'],
                "end_value": end_entity['value']
            }
            
            return self.neo4j.run_query(query, params)
            
        except Exception as e:
            logger.error(f"查找最短路径失败: {str(e)}")
            return []
    
    def get_entity_timeline(self, entity_type: str, entity_value: str) -> List[Dict[str, Any]]:
        """
        获取实体时间线
        
        Args:
            entity_type: 实体类型
            entity_value: 实体值
            
        Returns:
            时间线事件列表
        """
        try:
            query = f"""
            MATCH (entity:{entity_type} {{value: $entity_value}})
            OPTIONAL MATCH (entity)-[:CONTAINS]-(doc:Document)
            WHERE doc.created_at IS NOT NULL
            RETURN doc.created_at as timestamp, doc.source as source, 
                   doc.content as content
            ORDER BY doc.created_at DESC
            LIMIT 50
            """
            
            return self.neo4j.run_query(query, {"entity_value": entity_value})
            
        except Exception as e:
            logger.error(f"获取实体时间线失败: {str(e)}")
            return [] 