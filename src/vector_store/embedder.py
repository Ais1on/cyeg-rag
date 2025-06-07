"""
嵌入生成器 - 支持多种嵌入模型
"""
from typing import List, Dict, Any, Optional, Union
import numpy as np
from sentence_transformers import SentenceTransformer
import openai
import zhipuai
from loguru import logger
from ..utils.config import get_settings
from ..document_processor.chunker import DocumentChunk


class EmbeddingGenerator:
    """嵌入生成器"""
    
    def __init__(
        self, 
        model_name: str = None,
        model_type: str = "auto"
    ):
        """
        初始化嵌入生成器
        
        Args:
            model_name: 模型名称
            model_type: 模型类型 ("sentence_transformer", "openai", "zhipuai", "auto")
        """
        self.settings = get_settings()
        self.model_name = model_name or self.settings.embedding_model
        self.model_type = model_type
        self.model = None
        self.embedding_dim = None
        
        # 自动检测模型类型
        if self.model_type == "auto":
            self.model_type = self._detect_model_type()
        
        self._load_model()
    
    def _detect_model_type(self) -> str:
        """自动检测模型类型"""
        if "zhipuai" in self.model_name.lower() or "embedding-3" in self.model_name.lower() or "embedding-2" in self.model_name.lower():
            return "zhipuai"
        elif "text-embedding" in self.model_name.lower():
            return "openai"
        else:
            return "sentence_transformer"
    
    def _load_model(self):
        """加载嵌入模型"""
        try:
            if self.model_type == "sentence_transformer":
                logger.info(f"加载Sentence Transformer模型: {self.model_name}")
                self.model = SentenceTransformer(self.model_name)
                self.embedding_dim = self.model.get_sentence_embedding_dimension()
                
            elif self.model_type == "openai":
                logger.info(f"配置OpenAI嵌入模型: {self.model_name}")
                openai.api_key = self.settings.openai_api_key
                openai.base_url = self.settings.openai_base_url
                self.embedding_dim = 1536 if "ada" in self.model_name else 1536
                
            elif self.model_type == "zhipuai":
                logger.info(f"配置ZhipuAI嵌入模型: {self.model_name}")
                zhipuai.api_key = self.settings.zhipuai_api_key
                
                # 处理模型名称映射
                if "zhipuai-embedding-3" in self.model_name:
                    self.api_model_name = "embedding-3"
                    self.embedding_dim = 2048
                elif "zhipuai-embedding-2" in self.model_name:
                    self.api_model_name = "embedding-2"
                    self.embedding_dim = 1024
                elif "embedding-3" in self.model_name:
                    self.api_model_name = "embedding-3"
                    self.embedding_dim = 2048
                elif "embedding-2" in self.model_name:
                    self.api_model_name = "embedding-2"
                    self.embedding_dim = 1024
                else:
                    self.api_model_name = "embedding-3"  # 默认使用embedding-3
                    self.embedding_dim = 2048
                
            else:
                raise ValueError(f"不支持的模型类型: {self.model_type}")
                
            logger.info(f"模型加载成功，嵌入维度: {self.embedding_dim}")
            
        except Exception as e:
            logger.error(f"模型加载失败: {str(e)}")
            raise
    
    def generate_embeddings(
        self, 
        texts: Union[str, List[str]], 
        batch_size: int = 32
    ) -> Union[np.ndarray, List[np.ndarray]]:
        """
        生成文本嵌入
        
        Args:
            texts: 单个文本或文本列表
            batch_size: 批处理大小
            
        Returns:
            嵌入向量或嵌入向量列表
        """
        if isinstance(texts, str):
            return self._generate_single_embedding(texts)
        else:
            return self._generate_batch_embeddings(texts, batch_size)
    
    def _generate_single_embedding(self, text: str) -> np.ndarray:
        """生成单个文本的嵌入"""
        try:
            if self.model_type == "sentence_transformer":
                embedding = self.model.encode([text], show_progress_bar=False)[0]
                return embedding.astype(np.float32)
                
            elif self.model_type == "openai":
                response = openai.embeddings.create(
                    model=self.model_name,
                    input=text
                )
                embedding = np.array(response.data[0].embedding, dtype=np.float32)
                return embedding
                
            elif self.model_type == "zhipuai":
                client = zhipuai.ZhipuAI(api_key=self.settings.zhipuai_api_key)
                response = client.embeddings.create(
                    model=self.api_model_name,
                    input=text
                )
                embedding = np.array(response.data[0].embedding, dtype=np.float32)
                return embedding
                
        except Exception as e:
            logger.error(f"生成嵌入失败: {str(e)}")
            raise
    
    def _generate_batch_embeddings(
        self, 
        texts: List[str], 
        batch_size: int
    ) -> List[np.ndarray]:
        """批量生成嵌入"""
        embeddings = []
        
        try:
            if self.model_type == "sentence_transformer":
                # 分批处理
                for i in range(0, len(texts), batch_size):
                    batch_texts = texts[i:i + batch_size]
                    batch_embeddings = self.model.encode(
                        batch_texts, 
                        show_progress_bar=True,
                        batch_size=batch_size
                    )
                    embeddings.extend([emb.astype(np.float32) for emb in batch_embeddings])
                    
            elif self.model_type == "openai":
                # OpenAI API有速率限制
                import time
                for i in range(0, len(texts), min(batch_size, 100)):
                    batch_texts = texts[i:i + min(batch_size, 100)]
                    
                    response = openai.embeddings.create(
                        model=self.model_name,
                        input=batch_texts
                    )
                    
                    for data in response.data:
                        embedding = np.array(data.embedding, dtype=np.float32)
                        embeddings.append(embedding)
                    
                    if i + batch_size < len(texts):
                        time.sleep(0.1)
                        
            elif self.model_type == "zhipuai":
                # ZhipuAI API批量处理
                import time
                client = zhipuai.ZhipuAI(api_key=self.settings.zhipuai_api_key)
                
                for i in range(0, len(texts), min(batch_size, 25)):  # ZhipuAI建议的批量大小
                    batch_texts = texts[i:i + min(batch_size, 25)]
                    
                    response = client.embeddings.create(
                        model=self.api_model_name,
                        input=batch_texts
                    )
                    
                    for data in response.data:
                        embedding = np.array(data.embedding, dtype=np.float32)
                        embeddings.append(embedding)
                    
                    # 避免速率限制
                    if i + batch_size < len(texts):
                        time.sleep(0.2)
            
            logger.info(f"成功生成 {len(embeddings)} 个嵌入向量")
            return embeddings
            
        except Exception as e:
            logger.error(f"批量生成嵌入失败: {str(e)}")
            raise
    
    def embed_chunks(
        self, 
        chunks: List[DocumentChunk], 
        batch_size: int = 32
    ) -> List[DocumentChunk]:
        """
        为文档分块生成嵌入
        
        Args:
            chunks: 文档分块列表
            batch_size: 批处理大小
            
        Returns:
            包含嵌入的文档分块列表
        """
        logger.info(f"开始为 {len(chunks)} 个文档分块生成嵌入")
        
        # 提取文本内容
        texts = [chunk.content for chunk in chunks]
        
        # 生成嵌入
        embeddings = self.generate_embeddings(texts, batch_size)
        
        # 将嵌入添加到分块中
        for chunk, embedding in zip(chunks, embeddings):
            chunk.embedding = embedding
            chunk.metadata['embedding_model'] = self.model_name
            chunk.metadata['embedding_dim'] = self.embedding_dim
        
        logger.info("嵌入生成完成")
        return chunks
    
    def get_embedding(self, text: str) -> np.ndarray:
        """获取单个文本的嵌入向量"""
        return self._generate_single_embedding(text)
    
    def get_embedding_dim(self) -> int:
        """获取嵌入维度"""
        return self.embedding_dim
    
    def similarity(
        self, 
        embedding1: np.ndarray, 
        embedding2: np.ndarray,
        metric: str = "cosine"
    ) -> float:
        """
        计算两个嵌入向量的相似度
        
        Args:
            embedding1: 第一个嵌入向量
            embedding2: 第二个嵌入向量
            metric: 相似度度量方式 ("cosine", "euclidean", "dot")
            
        Returns:
            相似度分数
        """
        if metric == "cosine":
            # 余弦相似度
            norm1 = np.linalg.norm(embedding1)
            norm2 = np.linalg.norm(embedding2)
            if norm1 == 0 or norm2 == 0:
                return 0.0
            return np.dot(embedding1, embedding2) / (norm1 * norm2)
            
        elif metric == "euclidean":
            # 欧氏距离（转换为相似度）
            distance = np.linalg.norm(embedding1 - embedding2)
            return 1.0 / (1.0 + distance)
            
        elif metric == "dot":
            # 点积
            return np.dot(embedding1, embedding2)
            
        else:
            raise ValueError(f"不支持的相似度度量: {metric}")
    
    def find_most_similar(
        self, 
        query_embedding: np.ndarray,
        candidate_embeddings: List[np.ndarray],
        top_k: int = 5,
        metric: str = "cosine"
    ) -> List[tuple]:
        """
        查找最相似的嵌入向量
        
        Args:
            query_embedding: 查询嵌入向量
            candidate_embeddings: 候选嵌入向量列表
            top_k: 返回top-k结果
            metric: 相似度度量方式
            
        Returns:
            [(索引, 相似度分数), ...] 按相似度降序排列
        """
        similarities = []
        
        for i, candidate in enumerate(candidate_embeddings):
            similarity = self.similarity(query_embedding, candidate, metric)
            similarities.append((i, similarity))
        
        # 按相似度降序排序
        similarities.sort(key=lambda x: x[1], reverse=True)
        
        return similarities[:top_k]


class HybridEmbeddingGenerator:
    """混合嵌入生成器 - 结合多个模型"""
    
    def __init__(self, generators: List[EmbeddingGenerator], weights: List[float] = None):
        """
        初始化混合嵌入生成器
        
        Args:
            generators: 嵌入生成器列表
            weights: 各生成器的权重
        """
        self.generators = generators
        self.weights = weights or [1.0] * len(generators)
        
        if len(self.generators) != len(self.weights):
            raise ValueError("生成器数量与权重数量不匹配")
        
        # 计算混合后的嵌入维度
        self.embedding_dim = sum(
            gen.get_embedding_dim() * weight 
            for gen, weight in zip(self.generators, self.weights)
        )
    
    def generate_embeddings(
        self, 
        texts: Union[str, List[str]], 
        batch_size: int = 32
    ) -> Union[np.ndarray, List[np.ndarray]]:
        """生成混合嵌入"""
        all_embeddings = []
        
        # 从每个生成器获取嵌入
        for generator, weight in zip(self.generators, self.weights):
            embeddings = generator.generate_embeddings(texts, batch_size)
            
            if isinstance(texts, str):
                embeddings = embeddings * weight
            else:
                embeddings = [emb * weight for emb in embeddings]
            
            all_embeddings.append(embeddings)
        
        # 拼接嵌入
        if isinstance(texts, str):
            return np.concatenate(all_embeddings)
        else:
            hybrid_embeddings = []
            for i in range(len(texts)):
                embedding_parts = [embeddings[i] for embeddings in all_embeddings]
                hybrid_embedding = np.concatenate(embedding_parts)
                hybrid_embeddings.append(hybrid_embedding)
            return hybrid_embeddings
    
    def embed_chunks(
        self, 
        chunks: List[DocumentChunk], 
        batch_size: int = 32
    ) -> List[DocumentChunk]:
        """为文档分块生成混合嵌入"""
        logger.info(f"开始为 {len(chunks)} 个文档分块生成混合嵌入")
        
        texts = [chunk.content for chunk in chunks]
        embeddings = self.generate_embeddings(texts, batch_size)
        
        for chunk, embedding in zip(chunks, embeddings):
            chunk.embedding = embedding
            chunk.metadata['embedding_model'] = "hybrid"
            chunk.metadata['embedding_dim'] = len(embedding)
            chunk.metadata['hybrid_models'] = [gen.model_name for gen in self.generators]
            chunk.metadata['hybrid_weights'] = self.weights
        
        logger.info("混合嵌入生成完成")
        return chunks 