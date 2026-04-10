package symx

import (
	"fmt"
	"sync"
)

// ---------------------------------------------------------------------------
// 统一反混淆路由管理器
//
// DeobfuscatorManager 管理 buildId → Deobfuscator 的映射，
// 内置 Engine 缓存和自动路由，调用方只需提供 buildId 即可执行查询。
//
// 使用流程：
//  1. 创建 Manager，注入 Resolver（根据 buildId 解析文件路径）
//  2. 注册各文件类型的 DeobfuscatorFactory
//  3. 通过 Lookup / LookupStack 按 buildId 执行查询
//  4. 结束时调用 Close 释放所有缓存资源
//
// 示例：
//
//	mgr := symx.NewDeobfuscatorManager(symx.ResolverFunc(func(buildId string) (string, error) {
//	    return filepath.Join("/data/symbols", buildId+".symx"), nil
//	}))
//	mgr.Register(symx.ProGuard, func(e *symx.Engine) (symx.Deobfuscator, error) {
//	    return proguard.NewDecoder(e)
//	})
//	defer mgr.Close()
//
//	result, err := mgr.Lookup("abc123", symx.JavaLocation{Class: "a.b.c", Method: "a", Line: 42})
// ---------------------------------------------------------------------------

// Resolver 根据 buildId 解析出符号文件的路径。
// 由调用方提供，解耦文件存储策略（本地文件系统、对象存储、数据库等）。
type Resolver interface {
	Resolve(buildId string) (filePath string, err error)
}

// ResolverFunc 便捷类型，将普通函数适配为 Resolver 接口。
type ResolverFunc func(buildId string) (string, error)

// Resolve 实现 Resolver 接口。
func (f ResolverFunc) Resolve(buildId string) (string, error) { return f(buildId) }

// DeobfuscatorFactory 从已打开的 Engine 创建 Deobfuscator 实例。
type DeobfuscatorFactory func(e *Engine) (Deobfuscator, error)

// deobfuscatorEntry 缓存条目，持有 Engine 和对应的 Deobfuscator。
type deobfuscatorEntry struct {
	engine       *Engine
	deobfuscator Deobfuscator
}

// DeobfuscatorManager 管理 buildId → Deobfuscator 的映射。
// 内置 Engine 缓存和自动路由，线程安全。
type DeobfuscatorManager struct {
	resolver  Resolver
	factories map[uint8]DeobfuscatorFactory // fileType → factory
	cache     map[string]*deobfuscatorEntry // buildId → cached entry
	mu        sync.RWMutex
}

// NewDeobfuscatorManager 创建新的管理器实例。
// resolver 用于根据 buildId 解析符号文件路径，不能为 nil。
func NewDeobfuscatorManager(resolver Resolver) *DeobfuscatorManager {
	return &DeobfuscatorManager{
		resolver:  resolver,
		factories: make(map[uint8]DeobfuscatorFactory),
		cache:     make(map[string]*deobfuscatorEntry),
	}
}

// Register 注册一个文件类型对应的 Deobfuscator 工厂。
// 同一 fileType 重复注册时，后注册的覆盖先前的。
func (m *DeobfuscatorManager) Register(fileType uint8, factory DeobfuscatorFactory) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.factories[fileType] = factory
}

// getOrCreate 根据 buildId 获取缓存的 Deobfuscator，未命中时自动创建。
// 流程：读缓存 → Resolve 路径 → Open Engine → 选 Factory → 创建 Deobfuscator → 写缓存。
func (m *DeobfuscatorManager) getOrCreate(buildId string) (Deobfuscator, error) {
	// 快路径：读缓存
	m.mu.RLock()
	if entry, ok := m.cache[buildId]; ok {
		m.mu.RUnlock()
		return entry.deobfuscator, nil
	}
	m.mu.RUnlock()

	// 慢路径：创建
	m.mu.Lock()
	defer m.mu.Unlock()

	// Double-check：防止并发创建
	if entry, ok := m.cache[buildId]; ok {
		return entry.deobfuscator, nil
	}

	// 解析文件路径
	filePath, err := m.resolver.Resolve(buildId)
	if err != nil {
		return nil, fmt.Errorf("symx: resolve buildId %q: %w", buildId, err)
	}

	// 打开 Engine（mmap）
	engine, err := Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("symx: open %q: %w", filePath, err)
	}

	// 根据文件类型选择工厂
	fileType := engine.FileType()
	factory, ok := m.factories[fileType]
	if !ok {
		engine.Close()
		return nil, fmt.Errorf("symx: no factory registered for file type %d", fileType)
	}

	// 创建 Deobfuscator
	deobfuscator, err := factory(engine)
	if err != nil {
		engine.Close()
		return nil, fmt.Errorf("symx: create deobfuscator for buildId %q: %w", buildId, err)
	}

	// 写入缓存
	m.cache[buildId] = &deobfuscatorEntry{
		engine:       engine,
		deobfuscator: deobfuscator,
	}

	return deobfuscator, nil
}

// Lookup 根据 buildId 自动路由，执行单次反混淆查询。
// 首次访问某 buildId 时会自动解析路径、打开文件、创建 Decoder 并缓存。
func (m *DeobfuscatorManager) Lookup(buildId string, loc Location) (SymbolResult, error) {
	d, err := m.getOrCreate(buildId)
	if err != nil {
		return SymbolResult{}, err
	}
	return d.Lookup(loc), nil
}

// LookupStack 根据 buildId 自动路由，执行批量反混淆查询。
// 返回的切片与输入 locs 一一对应，顺序一致。
func (m *DeobfuscatorManager) LookupStack(buildId string, locs []Location) ([]SymbolResult, error) {
	d, err := m.getOrCreate(buildId)
	if err != nil {
		return nil, err
	}
	return d.LookupStack(locs), nil
}

// Close 关闭所有缓存的 Deobfuscator 和 Engine，释放 mmap 等资源。
// 调用 Close 后不应再使用此 Manager。
func (m *DeobfuscatorManager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	var firstErr error
	for buildId, entry := range m.cache {
		// 先关闭 Deobfuscator
		if err := entry.deobfuscator.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		// 再关闭 Engine（释放 mmap）
		if err := entry.engine.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		delete(m.cache, buildId)
	}

	return firstErr
}
