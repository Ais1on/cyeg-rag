"""
Milvus向量存储 - 高性能向量数据库存储和检索
"""
from typing import List, Dict, Any, Optional, Tuple
import numpy as np
from pymilvus import (
    connections, 
    Collection, 
    CollectionSchema, 
    FieldSchema, 
    DataType,
    utility
)
from loguru import logger
from ..utils.config import get_settings
from ..document_processor.chunker import DocumentChunk


class MilvusVectorStore:
    """Milvus向量存储"""
    
    def __init__(
        self,
        collection_name: str = "threat_intel_vectors",
        embedding_dim: int = 384,
        index_type: str = "IVF_FLAT",
        metric_type: str = "COSINE",
        auto_create: bool = True
    ):
        """
        初始化Milvus向量存储
        
        Args:
            collection_name: 集合名称
            embedding_dim: 嵌入维度
            index_type: 索引类型
            metric_type: 距离度量类型
            auto_create: 是否自动创建集合
        """
        self.settings = get_settings()
        self.collection_name = collection_name
        self.embedding_dim = embedding_dim
        self.index_type = index_type
        self.metric_type = metric_type
        self.collection = None
        
        self._connect()
        
        if auto_create:
            self._create_collection()
    
    def _connect(self):
        """连接到Milvus"""
        try:
            connections.connect(
                alias="default",
                host=self.settings.milvus_host,
                port=self.settings.milvus_port,
                user=self.settings.milvus_username,
                password=self.settings.milvus_password
            )
            logger.info(f"成功连接到Milvus: {self.settings.milvus_host}:{self.settings.milvus_port}")
            
        except Exception as e:
            logger.error(f"连接Milvus失败: {str(e)}")
            raise
    
    def _create_collection(self):
        """创建集合"""
        try:
            # 检查集合是否已存在
            if utility.has_collection(self.collection_name):
                logger.info(f"集合 {self.collection_name} 已存在，直接加载")
                self.collection = Collection(self.collection_name)
                return
            
            # 定义字段
            fields = [
                FieldSchema(
                    name="id", 
                    dtype=DataType.VARCHAR, 
                    is_primary=True, 
                    max_length=100
                ),
                FieldSchema(
                    name="embedding", 
                    dtype=DataType.FLOAT_VECTOR, 
                    dim=self.embedding_dim
                ),
                FieldSchema(
                    name="content", 
                    dtype=DataType.VARCHAR, 
                    max_length=65535
                ),
                FieldSchema(
                    name="metadata", 
                    dtype=DataType.JSON
                ),
                FieldSchema(
                    name="source", 
                    dtype=DataType.VARCHAR, 
                    max_length=500
                ),
                FieldSchema(
                    name="chunk_index", 
                    dtype=DataType.INT64
                ),
                FieldSchema(
                    name="embedding_model", 
                    dtype=DataType.VARCHAR, 
                    max_length=100
                )
            ]
            
            # 创建schema
            schema = CollectionSchema(
                fields=fields,
                description="威胁情报向量存储集合"
            )
            
            # 创建集合
            self.collection = Collection(
                name=self.collection_name,
                schema=schema
            )
            
            logger.info(f"成功创建集合: {self.collection_name}")
            
            # 创建索引
            self._create_index()
            
        except Exception as e:
            logger.error(f"创建集合失败: {str(e)}")
            raise
    
    def _create_index(self):
        """创建向量索引"""
        try:
            index_params = {
                "index_type": self.index_type,
                "metric_type": self.metric_type,
                "params": {"nlist": 128}  # IVF_FLAT参数
            }
            
            self.collection.create_index(
                field_name="embedding",
                index_params=index_params
            )
            
            logger.info(f"成功创建向量索引: {self.index_type}")
            
        except Exception as e:
            logger.error(f"创建索引失败: {str(e)}")
            raise
    
    def insert_chunks(self, chunks: List[DocumentChunk]) -> List[str]:
        """
        插入文档分块
        
        Args:
            chunks: 文档分块列表
            
        Returns:
            插入的ID列表
        """
        if not chunks:
            return []
        
        try:
            # 准备数据
            ids = []
            embeddings = []
            contents = []
            metadatas = []
            sources = []
            chunk_indices = []
            embedding_models = []
            
            for chunk in chunks:
                if chunk.embedding is None:
                    logger.warning(f"分块 {chunk.chunk_id} 没有嵌入向量，跳过")
                    continue
                
                chunk_id = chunk.chunk_id or f"chunk_{len(ids)}"
                
                ids.append(chunk_id)
                embeddings.append(chunk.embedding.tolist())
                contents.append(chunk.content[:65535])  # 截断过长内容
                metadatas.append(chunk.metadata)
                sources.append(chunk.metadata.get('source', '')[:500])
                chunk_indices.append(chunk.metadata.get('chunk_index', 0))
                embedding_models.append(chunk.metadata.get('embedding_model', '')[:100])
            
            if not ids:
                logger.warning("没有有效的分块可插入")
                return []
            
            # 插入数据
            data = [
                ids,
                embeddings,
                contents,
                metadatas,
                sources,
                chunk_indices,
                embedding_models
            ]
            
            insert_result = self.collection.insert(data)
            
            # 刷新以确保数据可见
            self.collection.flush()
            
            logger.info(f"成功插入 {len(ids)} 个向量")
            return ids
            
        except Exception as e:
            logger.error(f"插入向量失败: {str(e)}")
            raise
    
    def search(
        self,
        query_embedding: np.ndarray,
        top_k: int = 10,
        search_params: Dict = None,
        filter_expr: str = None
    ) -> List[Dict]:
        """
        向量搜索
        
        Args:
            query_embedding: 查询向量
            top_k: 返回前k个结果
            search_params: 搜索参数
            filter_expr: 过滤表达式
            
        Returns:
            搜索结果列表
        """
        try:
            # 确保集合已加载
            self.collection.load()
            
            # 默认搜索参数
            if search_params is None:
                search_params = {"metric_type": self.metric_type, "params": {"nprobe": 10}}
            
            # 执行搜索
            results = self.collection.search(
                data=[query_embedding.tolist()],
                anns_field="embedding",
                param=search_params,
                limit=top_k,
                expr=filter_expr,
                output_fields=["content", "metadata", "source", "chunk_index", "embedding_model"]
            )
            
            # 处理结果
            formatted_results = []
            for hits in results:
                for hit in hits:
                    result = {
                        'id': hit.id,
                        'score': hit.score,
                        'content': hit.entity.get('content'),
                        'metadata': hit.entity.get('metadata'),
                        'source': hit.entity.get('source'),
                        'chunk_index': hit.entity.get('chunk_index'),
                        'embedding_model': hit.entity.get('embedding_model')
                    }
                    formatted_results.append(result)
            
            logger.info(f"搜索完成，返回 {len(formatted_results)} 个结果")
            return formatted_results
            
        except Exception as e:
            logger.error(f"向量搜索失败: {str(e)}")
            raise
    
    def hybrid_search(
        self,
        query_embedding: np.ndarray,
        keywords: List[str] = None,
        sources: List[str] = None,
        top_k: int = 10,
        vector_weight: float = 0.7,
        keyword_weight: float = 0.3
    ) -> List[Dict]:
        """
        混合搜索 - 结合向量搜索和关键词过滤
        
        Args:
            query_embedding: 查询向量
            keywords: 关键词列表
            sources: 源文件列表
            top_k: 返回前k个结果
            vector_weight: 向量搜索权重
            keyword_weight: 关键词搜索权重
            
        Returns:
            混合搜索结果
        """
        try:
            # 构建过滤表达式
            filter_conditions = []
            
            if sources:
                source_condition = " or ".join([f'source like "%{src}%"' for src in sources])
                filter_conditions.append(f"({source_condition})")
            
            if keywords:
                keyword_condition = " or ".join([f'content like "%{kw}%"' for kw in keywords])
                filter_conditions.append(f"({keyword_condition})")
            
            filter_expr = " and ".join(filter_conditions) if filter_conditions else None
            
            # 执行向量搜索
            vector_results = self.search(
                query_embedding=query_embedding,
                top_k=top_k * 2,  # 获取更多结果用于重排序
                filter_expr=filter_expr
            )
            
            # 关键词匹配评分
            if keywords:
                for result in vector_results:
                    content = result['content'].lower()
                    keyword_score = sum(1 for kw in keywords if kw.lower() in content) / len(keywords)
                    
                    # 组合评分
                    combined_score = (vector_weight * result['score'] + 
                                    keyword_weight * keyword_score)
                    result['combined_score'] = combined_score
                    result['keyword_score'] = keyword_score
                
                # 按组合评分重新排序
                vector_results.sort(key=lambda x: x.get('combined_score', x['score']), reverse=True)
            
            return vector_results[:top_k]
            
        except Exception as e:
            logger.error(f"混合搜索失败: {str(e)}")
            raise
    
    def get_by_ids(self, ids: List[str]) -> List[Dict]:
        """根据ID获取向量"""
        try:
            self.collection.load()
            
            results = self.collection.query(
                expr=f'id in {ids}',
                output_fields=["content", "metadata", "source", "chunk_index", "embedding_model", "embedding"]
            )
            
            return results
            
        except Exception as e:
            logger.error(f"根据ID获取向量失败: {str(e)}")
            raise
    
    def delete_by_ids(self, ids: List[str]) -> bool:
        """根据ID删除向量"""
        try:
            delete_expr = f'id in {ids}'
            self.collection.delete(delete_expr)
            self.collection.flush()
            
            logger.info(f"成功删除 {len(ids)} 个向量")
            return True
            
        except Exception as e:
            logger.error(f"删除向量失败: {str(e)}")
            return False
    
    def delete_by_source(self, source: str) -> bool:
        """根据源文件删除向量"""
        try:
            delete_expr = f'source == "{source}"'
            self.collection.delete(delete_expr)
            self.collection.flush()
            
            logger.info(f"成功删除源文件 {source} 的所有向量")
            return True
            
        except Exception as e:
            logger.error(f"删除源文件向量失败: {str(e)}")
            return False
    
    def get_stats(self) -> Dict:
        """获取集合统计信息"""
        try:
            self.collection.load()
            
            stats = {
                'total_entities': self.collection.num_entities,
                'collection_name': self.collection_name,
                'embedding_dim': self.embedding_dim,
                'index_type': self.index_type,
                'metric_type': self.metric_type
            }
            
            return stats
            
        except Exception as e:
            logger.error(f"获取统计信息失败: {str(e)}")
            return {}
    
    def create_alias(self, alias_name: str):
        """为集合创建别名"""
        try:
            utility.create_alias(self.collection_name, alias_name)
            logger.info(f"为集合 {self.collection_name} 创建别名: {alias_name}")
            
        except Exception as e:
            logger.error(f"创建别名失败: {str(e)}")
            raise
    
    def drop_collection(self):
        """删除集合"""
        try:
            if utility.has_collection(self.collection_name):
                utility.drop_collection(self.collection_name)
                logger.info(f"成功删除集合: {self.collection_name}")
            else:
                logger.warning(f"集合 {self.collection_name} 不存在")
                
        except Exception as e:
            logger.error(f"删除集合失败: {str(e)}")
            raise
    
    def backup_collection(self, backup_path: str):
        """备份集合（导出数据）"""
        try:
            self.collection.load()
            
            # 获取所有数据
            query_result = self.collection.query(
                expr="",
                output_fields=["id", "content", "metadata", "source", "chunk_index", "embedding_model"]
            )
            
            # 保存到文件
            import json
            with open(backup_path, 'w', encoding='utf-8') as f:
                json.dump(query_result, f, ensure_ascii=False, indent=2)
            
            logger.info(f"集合数据已备份到: {backup_path}")
            
        except Exception as e:
            logger.error(f"备份集合失败: {str(e)}")
            raise 