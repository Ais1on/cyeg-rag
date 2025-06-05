"""
文档分块器 - 支持多种分块策略
"""
import re
from typing import List, Dict, Any, Optional
from enum import Enum
from loguru import logger
from .loader import Document


class ChunkStrategy(Enum):
    """分块策略"""
    FIXED_SIZE = "fixed_size"  # 固定大小分块
    SENTENCE = "sentence"      # 按句子分块
    PARAGRAPH = "paragraph"    # 按段落分块
    SEMANTIC = "semantic"      # 语义分块
    THREAT_INTEL = "threat_intel"  # 威胁情报专用分块


class DocumentChunk:
    """文档分块数据结构"""
    
    def __init__(self, content: str, metadata: Dict[str, Any] = None, chunk_id: str = None):
        self.content = content
        self.metadata = metadata or {}
        self.chunk_id = chunk_id
        self.embedding = None  # 向量嵌入
    
    def __repr__(self):
        return f"DocumentChunk(id={self.chunk_id}, content_length={len(self.content)})"


class DocumentChunker:
    """文档分块器"""
    
    def __init__(
        self,
        chunk_size: int = 512,
        chunk_overlap: int = 50,
        strategy: ChunkStrategy = ChunkStrategy.FIXED_SIZE
    ):
        self.chunk_size = chunk_size
        self.chunk_overlap = chunk_overlap
        self.strategy = strategy
        
        # 威胁情报关键词模式
        self.threat_patterns = {
            'ioc': r'\b(?:(?:\d{1,3}\.){3}\d{1,3}|[a-fA-F0-9]{32,64}|(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,})\b',
            'cve': r'CVE-\d{4}-\d{4,}',
            'mitre': r'T\d{4}(?:\.\d{3})?',
            'malware': r'\b(?:malware|trojan|virus|ransomware|backdoor|rootkit|spyware|adware)\b',
            'campaign': r'\b(?:apt|campaign|operation|group)\s+\w+\b'
        }
    
    def chunk_document(self, document: Document) -> List[DocumentChunk]:
        """对文档进行分块"""
        logger.info(f"开始分块文档，策略: {self.strategy.value}")
        
        if self.strategy == ChunkStrategy.FIXED_SIZE:
            return self._chunk_fixed_size(document)
        elif self.strategy == ChunkStrategy.SENTENCE:
            return self._chunk_by_sentence(document)
        elif self.strategy == ChunkStrategy.PARAGRAPH:
            return self._chunk_by_paragraph(document)
        elif self.strategy == ChunkStrategy.SEMANTIC:
            return self._chunk_semantic(document)
        elif self.strategy == ChunkStrategy.THREAT_INTEL:
            return self._chunk_threat_intel(document)
        else:
            raise ValueError(f"不支持的分块策略: {self.strategy}")
    
    def chunk_documents(self, documents: List[Document]) -> List[DocumentChunk]:
        """批量分块文档"""
        all_chunks = []
        
        for i, doc in enumerate(documents):
            try:
                chunks = self.chunk_document(doc)
                # 为每个分块添加全局ID
                for j, chunk in enumerate(chunks):
                    chunk.chunk_id = f"doc_{i}_chunk_{j}"
                    chunk.metadata['document_index'] = i
                    chunk.metadata['chunk_index'] = j
                
                all_chunks.extend(chunks)
                
            except Exception as e:
                logger.error(f"分块文档失败 (索引 {i}): {str(e)}")
                continue
        
        logger.info(f"总共生成 {len(all_chunks)} 个文档分块")
        return all_chunks
    
    def _chunk_fixed_size(self, document: Document) -> List[DocumentChunk]:
        """固定大小分块"""
        text = document.content
        chunks = []
        
        start = 0
        chunk_index = 0
        
        while start < len(text):
            # 计算当前分块的结束位置
            end = start + self.chunk_size
            
            # 如果不是最后一个分块，尝试在单词边界结束
            if end < len(text):
                # 向后查找最近的空格
                while end > start and text[end] != ' ' and text[end] != '\n':
                    end -= 1
                
                # 如果没找到合适的分割点，就按原来的大小分割
                if end == start:
                    end = start + self.chunk_size
            
            chunk_text = text[start:end].strip()
            
            if chunk_text:
                metadata = {
                    **document.metadata,
                    'chunk_index': chunk_index,
                    'start_pos': start,
                    'end_pos': end,
                    'chunk_strategy': self.strategy.value
                }
                
                chunks.append(DocumentChunk(
                    content=chunk_text,
                    metadata=metadata
                ))
                
                chunk_index += 1
            
            # 计算下一个分块的起始位置（考虑重叠）
            start = max(start + 1, end - self.chunk_overlap)
        
        return chunks
    
    def _chunk_by_sentence(self, document: Document) -> List[DocumentChunk]:
        """按句子分块"""
        text = document.content
        
        # 句子分割正则表达式
        sentence_pattern = r'(?<=[.!?])\s+'
        sentences = re.split(sentence_pattern, text)
        
        chunks = []
        current_chunk = ""
        chunk_index = 0
        
        for sentence in sentences:
            sentence = sentence.strip()
            if not sentence:
                continue
            
            # 如果加上当前句子会超过大小限制，先保存当前分块
            if len(current_chunk + sentence) > self.chunk_size and current_chunk:
                metadata = {
                    **document.metadata,
                    'chunk_index': chunk_index,
                    'chunk_strategy': self.strategy.value,
                    'sentence_count': len(re.split(sentence_pattern, current_chunk))
                }
                
                chunks.append(DocumentChunk(
                    content=current_chunk.strip(),
                    metadata=metadata
                ))
                
                chunk_index += 1
                current_chunk = ""
            
            current_chunk += sentence + " "
        
        # 处理最后一个分块
        if current_chunk.strip():
            metadata = {
                **document.metadata,
                'chunk_index': chunk_index,
                'chunk_strategy': self.strategy.value,
                'sentence_count': len(re.split(sentence_pattern, current_chunk))
            }
            
            chunks.append(DocumentChunk(
                content=current_chunk.strip(),
                metadata=metadata
            ))
        
        return chunks
    
    def _chunk_by_paragraph(self, document: Document) -> List[DocumentChunk]:
        """按段落分块"""
        text = document.content
        paragraphs = [p.strip() for p in text.split('\n\n') if p.strip()]
        
        chunks = []
        current_chunk = ""
        chunk_index = 0
        
        for paragraph in paragraphs:
            # 如果单个段落就超过大小限制，需要进一步分割
            if len(paragraph) > self.chunk_size:
                # 如果当前有内容，先保存
                if current_chunk:
                    metadata = {
                        **document.metadata,
                        'chunk_index': chunk_index,
                        'chunk_strategy': self.strategy.value
                    }
                    
                    chunks.append(DocumentChunk(
                        content=current_chunk.strip(),
                        metadata=metadata
                    ))
                    
                    chunk_index += 1
                    current_chunk = ""
                
                # 对大段落进行分割
                sub_chunks = self._split_large_text(paragraph, document.metadata, chunk_index)
                chunks.extend(sub_chunks)
                chunk_index += len(sub_chunks)
                
            else:
                # 检查是否会超过大小限制
                if len(current_chunk + paragraph) > self.chunk_size and current_chunk:
                    metadata = {
                        **document.metadata,
                        'chunk_index': chunk_index,
                        'chunk_strategy': self.strategy.value
                    }
                    
                    chunks.append(DocumentChunk(
                        content=current_chunk.strip(),
                        metadata=metadata
                    ))
                    
                    chunk_index += 1
                    current_chunk = ""
                
                current_chunk += paragraph + "\n\n"
        
        # 处理最后一个分块
        if current_chunk.strip():
            metadata = {
                **document.metadata,
                'chunk_index': chunk_index,
                'chunk_strategy': self.strategy.value
            }
            
            chunks.append(DocumentChunk(
                content=current_chunk.strip(),
                metadata=metadata
            ))
        
        return chunks
    
    def _chunk_semantic(self, document: Document) -> List[DocumentChunk]:
        """语义分块（简化版本，基于主题边界）"""
        # 这里实现一个简化的语义分块
        # 在实际应用中，可以使用更复杂的NLP技术
        
        text = document.content
        paragraphs = [p.strip() for p in text.split('\n\n') if p.strip()]
        
        chunks = []
        current_chunk = ""
        chunk_index = 0
        
        for i, paragraph in enumerate(paragraphs):
            # 简单的主题变化检测（基于关键词变化）
            topic_change = self._detect_topic_change(
                current_chunk, paragraph
            ) if current_chunk else False
            
            # 如果主题变化或大小超限，创建新分块
            if (topic_change or len(current_chunk + paragraph) > self.chunk_size) and current_chunk:
                metadata = {
                    **document.metadata,
                    'chunk_index': chunk_index,
                    'chunk_strategy': self.strategy.value,
                    'topic_boundary': topic_change
                }
                
                chunks.append(DocumentChunk(
                    content=current_chunk.strip(),
                    metadata=metadata
                ))
                
                chunk_index += 1
                current_chunk = ""
            
            current_chunk += paragraph + "\n\n"
        
        # 处理最后一个分块
        if current_chunk.strip():
            metadata = {
                **document.metadata,
                'chunk_index': chunk_index,
                'chunk_strategy': self.strategy.value
            }
            
            chunks.append(DocumentChunk(
                content=current_chunk.strip(),
                metadata=metadata
            ))
        
        return chunks
    
    def _chunk_threat_intel(self, document: Document) -> List[DocumentChunk]:
        """威胁情报专用分块"""
        text = document.content
        chunks = []
        
        # 检测威胁情报实体
        entities = self._extract_threat_entities(text)
        
        # 基于威胁情报实体进行智能分块
        chunks = self._smart_chunk_with_entities(text, entities, document.metadata)
        
        return chunks
    
    def _extract_threat_entities(self, text: str) -> Dict[str, List[Dict]]:
        """提取威胁情报实体"""
        entities = {}
        
        for entity_type, pattern in self.threat_patterns.items():
            matches = []
            for match in re.finditer(pattern, text, re.IGNORECASE):
                matches.append({
                    'text': match.group(),
                    'start': match.start(),
                    'end': match.end(),
                    'type': entity_type
                })
            entities[entity_type] = matches
        
        return entities
    
    def _smart_chunk_with_entities(
        self, 
        text: str, 
        entities: Dict[str, List[Dict]], 
        base_metadata: Dict
    ) -> List[DocumentChunk]:
        """基于实体的智能分块"""
        chunks = []
        
        # 获取所有实体位置
        all_entities = []
        for entity_type, entity_list in entities.items():
            all_entities.extend(entity_list)
        
        # 按位置排序
        all_entities.sort(key=lambda x: x['start'])
        
        if not all_entities:
            # 如果没有实体，回退到固定大小分块
            return self._chunk_fixed_size_with_metadata(text, base_metadata)
        
        # 基于实体位置进行分块
        start = 0
        chunk_index = 0
        
        for i, entity in enumerate(all_entities):
            # 计算包含当前实体的分块边界
            chunk_start = max(start, entity['start'] - self.chunk_size // 2)
            chunk_end = min(len(text), entity['end'] + self.chunk_size // 2)
            
            # 调整到单词边界
            while chunk_start > 0 and text[chunk_start] != ' ':
                chunk_start -= 1
            while chunk_end < len(text) and text[chunk_end] != ' ':
                chunk_end += 1
            
            chunk_text = text[chunk_start:chunk_end].strip()
            
            if chunk_text and len(chunk_text) > 50:  # 最小分块大小
                # 统计该分块中的实体
                chunk_entities = []
                for e in all_entities:
                    if chunk_start <= e['start'] < chunk_end:
                        chunk_entities.append(e)
                
                metadata = {
                    **base_metadata,
                    'chunk_index': chunk_index,
                    'chunk_strategy': self.strategy.value,
                    'threat_entities': chunk_entities,
                    'entity_count': len(chunk_entities),
                    'start_pos': chunk_start,
                    'end_pos': chunk_end
                }
                
                chunks.append(DocumentChunk(
                    content=chunk_text,
                    metadata=metadata
                ))
                
                chunk_index += 1
                start = chunk_end - self.chunk_overlap
        
        return chunks
    
    def _chunk_fixed_size_with_metadata(self, text: str, base_metadata: Dict) -> List[DocumentChunk]:
        """带元数据的固定大小分块"""
        chunks = []
        start = 0
        chunk_index = 0
        
        while start < len(text):
            end = start + self.chunk_size
            
            if end < len(text):
                while end > start and text[end] != ' ':
                    end -= 1
                if end == start:
                    end = start + self.chunk_size
            
            chunk_text = text[start:end].strip()
            
            if chunk_text:
                metadata = {
                    **base_metadata,
                    'chunk_index': chunk_index,
                    'chunk_strategy': self.strategy.value
                }
                
                chunks.append(DocumentChunk(
                    content=chunk_text,
                    metadata=metadata
                ))
                
                chunk_index += 1
            
            start = max(start + 1, end - self.chunk_overlap)
        
        return chunks
    
    def _detect_topic_change(self, current_text: str, new_paragraph: str) -> bool:
        """检测主题变化（简化版本）"""
        if not current_text:
            return False
        
        # 提取关键词
        current_keywords = set(re.findall(r'\b[a-zA-Z]{4,}\b', current_text.lower()))
        new_keywords = set(re.findall(r'\b[a-zA-Z]{4,}\b', new_paragraph.lower()))
        
        # 计算词汇重叠度
        if not current_keywords or not new_keywords:
            return False
        
        overlap = len(current_keywords & new_keywords)
        overlap_ratio = overlap / min(len(current_keywords), len(new_keywords))
        
        # 如果重叠度小于阈值，认为主题发生变化
        return overlap_ratio < 0.3
    
    def _split_large_text(self, text: str, base_metadata: Dict, start_index: int) -> List[DocumentChunk]:
        """分割过大的文本"""
        chunks = []
        start = 0
        chunk_index = start_index
        
        while start < len(text):
            end = start + self.chunk_size
            
            if end < len(text):
                while end > start and text[end] != ' ':
                    end -= 1
                if end == start:
                    end = start + self.chunk_size
            
            chunk_text = text[start:end].strip()
            
            if chunk_text:
                metadata = {
                    **base_metadata,
                    'chunk_index': chunk_index,
                    'chunk_strategy': self.strategy.value,
                    'split_from_large': True
                }
                
                chunks.append(DocumentChunk(
                    content=chunk_text,
                    metadata=metadata
                ))
                
                chunk_index += 1
            
            start = max(start + 1, end - self.chunk_overlap)
        
        return chunks 