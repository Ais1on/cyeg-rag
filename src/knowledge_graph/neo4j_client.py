"""
Neo4j数据库客户端
"""
from typing import Dict, List, Any, Optional
from neo4j import GraphDatabase
from loguru import logger
from ..utils.config import get_settings


class Neo4jClient:
    """Neo4j数据库客户端"""
    
    def __init__(self, uri: str = None, username: str = None, password: str = None):
        """
        初始化Neo4j客户端
        
        Args:
            uri: Neo4j连接URI
            username: 用户名
            password: 密码
        """
        self.settings = get_settings()
        
        self.uri = uri or self.settings.neo4j_uri
        self.username = username or self.settings.neo4j_username
        self.password = password or self.settings.neo4j_password
        
        self.driver = None
        self._connect()
    
    def _connect(self):
        """连接到Neo4j数据库"""
        try:
            self.driver = GraphDatabase.driver(
                self.uri,
                auth=(self.username, self.password)
            )
            
            # 测试连接
            with self.driver.session() as session:
                session.run("RETURN 1")
            
            logger.info(f"成功连接到Neo4j: {self.uri}")
            
        except Exception as e:
            logger.error(f"连接Neo4j失败: {str(e)}")
            raise
    
    def close(self):
        """关闭连接"""
        if self.driver:
            self.driver.close()
            logger.info("Neo4j连接已关闭")
    
    def run_query(self, query: str, parameters: Dict = None) -> List[Dict]:
        """
        执行Cypher查询
        
        Args:
            query: Cypher查询语句
            parameters: 查询参数
            
        Returns:
            查询结果列表
        """
        try:
            with self.driver.session() as session:
                result = session.run(query, parameters or {})
                records = [record.data() for record in result]
                return records
                
        except Exception as e:
            logger.error(f"执行Neo4j查询失败: {str(e)}")
            logger.error(f"查询语句: {query}")
            raise
    
    def create_node(
        self,
        label: str,
        properties: Dict[str, Any],
        merge: bool = True
    ) -> Dict:
        """
        创建节点
        
        Args:
            label: 节点标签
            properties: 节点属性
            merge: 是否使用MERGE（避免重复）
            
        Returns:
            创建的节点信息
        """
        try:
            # 构建属性字符串
            props_str = ", ".join([f"{k}: ${k}" for k in properties.keys()])
            
            if merge:
                query = f"MERGE (n:{label} {{{props_str}}}) RETURN n"
            else:
                query = f"CREATE (n:{label} {{{props_str}}}) RETURN n"
            
            result = self.run_query(query, properties)
            return result[0]['n'] if result else None
            
        except Exception as e:
            logger.error(f"创建节点失败: {str(e)}")
            raise
    
    def create_relationship(
        self,
        from_node: Dict[str, Any],
        to_node: Dict[str, Any],
        relationship_type: str,
        properties: Dict[str, Any] = None
    ) -> Dict:
        """
        创建关系
        
        Args:
            from_node: 起始节点 {"label": "Label", "key": "value"}
            to_node: 目标节点 {"label": "Label", "key": "value"}
            relationship_type: 关系类型
            properties: 关系属性
            
        Returns:
            创建的关系信息
        """
        try:
            # 构建节点匹配条件
            from_condition = self._build_node_condition("a", from_node)
            to_condition = self._build_node_condition("b", to_node)
            
            # 构建关系属性
            rel_props = ""
            if properties:
                props_str = ", ".join([f"{k}: ${k}" for k in properties.keys()])
                rel_props = f" {{{props_str}}}"
            
            query = f"""
            MATCH {from_condition}
            MATCH {to_condition}
            MERGE (a)-[r:{relationship_type}{rel_props}]->(b)
            RETURN r
            """
            
            params = {**from_node, **to_node}
            if properties:
                params.update(properties)
            
            result = self.run_query(query, params)
            return result[0]['r'] if result else None
            
        except Exception as e:
            logger.error(f"创建关系失败: {str(e)}")
            raise
    
    def find_nodes(
        self,
        label: str = None,
        properties: Dict[str, Any] = None,
        limit: int = 100
    ) -> List[Dict]:
        """
        查找节点
        
        Args:
            label: 节点标签
            properties: 查找条件
            limit: 结果数量限制
            
        Returns:
            节点列表
        """
        try:
            conditions = []
            params = {}
            
            # 构建标签条件
            label_part = f":{label}" if label else ""
            
            # 构建属性条件
            if properties:
                for key, value in properties.items():
                    conditions.append(f"n.{key} = ${key}")
                    params[key] = value
            
            where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""
            
            query = f"MATCH (n{label_part}) {where_clause} RETURN n LIMIT {limit}"
            
            result = self.run_query(query, params)
            return [record['n'] for record in result]
            
        except Exception as e:
            logger.error(f"查找节点失败: {str(e)}")
            raise
    
    def find_relationships(
        self,
        from_label: str = None,
        to_label: str = None,
        relationship_type: str = None,
        limit: int = 100
    ) -> List[Dict]:
        """
        查找关系
        
        Args:
            from_label: 起始节点标签
            to_label: 目标节点标签
            relationship_type: 关系类型
            limit: 结果数量限制
            
        Returns:
            关系列表
        """
        try:
            from_part = f":{from_label}" if from_label else ""
            to_part = f":{to_label}" if to_label else ""
            rel_part = f":{relationship_type}" if relationship_type else ""
            
            query = f"""
            MATCH (a{from_part})-[r{rel_part}]->(b{to_part})
            RETURN a, r, b
            LIMIT {limit}
            """
            
            return self.run_query(query)
            
        except Exception as e:
            logger.error(f"查找关系失败: {str(e)}")
            raise
    
    def delete_node(self, label: str, properties: Dict[str, Any]) -> bool:
        """删除节点"""
        try:
            condition = self._build_node_condition("n", {"label": label, **properties})
            query = f"MATCH {condition} DETACH DELETE n"
            
            self.run_query(query, properties)
            logger.info(f"删除节点: {label} {properties}")
            return True
            
        except Exception as e:
            logger.error(f"删除节点失败: {str(e)}")
            return False
    
    def get_graph_stats(self) -> Dict[str, Any]:
        """获取图数据库统计信息"""
        try:
            stats = {}
            
            # 节点统计
            node_count_query = "MATCH (n) RETURN count(n) as node_count"
            result = self.run_query(node_count_query)
            stats['total_nodes'] = result[0]['node_count'] if result else 0
            
            # 关系统计
            rel_count_query = "MATCH ()-[r]->() RETURN count(r) as rel_count"
            result = self.run_query(rel_count_query)
            stats['total_relationships'] = result[0]['rel_count'] if result else 0
            
            # 标签统计
            labels_query = "CALL db.labels() YIELD label RETURN collect(label) as labels"
            result = self.run_query(labels_query)
            stats['labels'] = result[0]['labels'] if result else []
            
            # 关系类型统计
            rel_types_query = "CALL db.relationshipTypes() YIELD relationshipType RETURN collect(relationshipType) as types"
            result = self.run_query(rel_types_query)
            stats['relationship_types'] = result[0]['types'] if result else []
            
            return stats
            
        except Exception as e:
            logger.error(f"获取图统计信息失败: {str(e)}")
            return {}
    
    def clear_database(self):
        """清空数据库（谨慎使用）"""
        try:
            query = "MATCH (n) DETACH DELETE n"
            self.run_query(query)
            logger.info("数据库已清空")
            
        except Exception as e:
            logger.error(f"清空数据库失败: {str(e)}")
            raise
    
    def _build_node_condition(self, var_name: str, node_spec: Dict[str, Any]) -> str:
        """构建节点匹配条件"""
        label = node_spec.get('label', '')
        label_part = f":{label}" if label else ""
        
        # 构建属性条件
        properties = {k: v for k, v in node_spec.items() if k != 'label'}
        if properties:
            props_str = ", ".join([f"{k}: ${k}" for k in properties.keys()])
            return f"({var_name}{label_part} {{{props_str}}})"
        else:
            return f"({var_name}{label_part})"
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
    
    