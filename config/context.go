package config

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/gin-gonic/gin"
	"io"
	"math"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/RussellLuo/timingwheel"
	"github.com/TangSengDaoDao/TangSengDaoDaoServerLib/common"
	"github.com/TangSengDaoDao/TangSengDaoDaoServerLib/pkg/cache"
	"github.com/TangSengDaoDao/TangSengDaoDaoServerLib/pkg/db"
	"github.com/TangSengDaoDao/TangSengDaoDaoServerLib/pkg/log"
	"github.com/TangSengDaoDao/TangSengDaoDaoServerLib/pkg/pool"
	"github.com/TangSengDaoDao/TangSengDaoDaoServerLib/pkg/redis"
	"github.com/TangSengDaoDao/TangSengDaoDaoServerLib/pkg/wkevent"
	"github.com/TangSengDaoDao/TangSengDaoDaoServerLib/pkg/wkhttp"
	"github.com/bwmarrin/snowflake"
	"github.com/gocraft/dbr/v2"
	"github.com/olivere/elastic"
	"github.com/opentracing/opentracing-go"
)

// Context 配置上下文
type Context struct {
	cfg          *Config
	mySQLSession *dbr.Session
	redisCache   *common.RedisCache
	memoryCache  cache.Cache
	log.Log
	EventPool      pool.Collector
	PushPool       pool.Collector // 离线push
	RobotEventPool pool.Collector // 机器人事件pool
	Event          wkevent.Event
	elasticClient  *elastic.Client
	UserIDGen      *snowflake.Node          // 消息ID生成器
	tracer         *Tracer                  // 调用链追踪
	aysncTask      *AsyncTask               // 异步任务
	timingWheel    *timingwheel.TimingWheel // Time wheel delay task

	httpRouter *wkhttp.WKHttp

	valueMap  sync.Map
	SetupTask bool // 是否安装task
}

// NewContext NewContext
func NewContext(cfg *Config) *Context {
	userIDGen, err := snowflake.NewNode(int64(cfg.Cluster.NodeID))
	if err != nil {
		panic(err)
	}
	c := &Context{
		cfg:            cfg,
		UserIDGen:      userIDGen,
		Log:            log.NewTLog("Context"),
		EventPool:      pool.StartDispatcher(cfg.EventPoolSize),
		PushPool:       pool.StartDispatcher(cfg.Push.PushPoolSize),
		RobotEventPool: pool.StartDispatcher(cfg.Robot.EventPoolSize),
		aysncTask:      NewAsyncTask(cfg),
		timingWheel:    timingwheel.NewTimingWheel(cfg.TimingWheelTick.Duration, cfg.TimingWheelSize),
		valueMap:       sync.Map{},
	}
	c.tracer, err = NewTracer(cfg)
	if err != nil {
		panic(err)
	}
	opentracing.SetGlobalTracer(c.tracer)
	c.timingWheel.Start()
	return c
}

// GetConfig 获取配置信息
func (c *Context) GetConfig() *Config {
	return c.cfg
}

// NewMySQL 创建mysql数据库实例
func (c *Context) NewMySQL() *dbr.Session {

	if c.mySQLSession == nil {
		c.mySQLSession = db.NewMySQL(c.cfg.DB.MySQLAddr, c.cfg.DB.MySQLMaxOpenConns, c.cfg.DB.MySQLMaxIdleConns, c.cfg.DB.MySQLConnMaxLifetime)
	}

	return c.mySQLSession
}

// AsyncTask 异步任务
func (c *Context) AsyncTask() *AsyncTask {
	return c.aysncTask
}

// Tracer Tracer
func (c *Context) Tracer() *Tracer {
	return c.tracer
}

// DB DB
func (c *Context) DB() *dbr.Session {
	return c.NewMySQL()
}

// NewRedisCache 创建一个redis缓存
func (c *Context) NewRedisCache() *common.RedisCache {
	if c.redisCache == nil {
		c.redisCache = common.NewRedisCache(c.cfg.DB.RedisAddr, c.cfg.DB.RedisPass)
	}
	return c.redisCache
}

// NewMemoryCache 创建一个内存缓存
func (c *Context) NewMemoryCache() cache.Cache {
	if c.memoryCache == nil {
		c.memoryCache = common.NewMemoryCache()
	}
	return c.memoryCache
}

// Cache 缓存
func (c *Context) Cache() cache.Cache {
	return c.NewRedisCache()
}

// 认证中间件
func (c *Context) AuthMiddleware(r *wkhttp.WKHttp) wkhttp.HandlerFunc {

	return r.AuthMiddleware(c.Cache(), c.cfg.Cache.TokenCachePrefix)
}

// 认证中间件 - Token + IP白名单 + RBAC权限
func (c *Context) AuthMiddlewareForIpRBAC(r *wkhttp.WKHttp) wkhttp.HandlerFunc {
	return func(ctx *wkhttp.Context) {

		// Token 校验
		c.checkAuth(ctx, c.Cache(), c.cfg.Cache.TokenCachePrefix)
		if ctx.IsAborted() {
			return
		}

		// IP 白名单
		c.checkAdminIPWhitelist(ctx)
		if ctx.IsAborted() {
			return
		}

		// RBAC 权限
		c.checkAdminPermission(ctx)
		if ctx.IsAborted() {
			return
		}

		ctx.Next()
	}
}

// 认证中间件 - 签名
func (c *Context) AuthMiddlewareForSign(secret string) wkhttp.HandlerFunc {
	return func(ctx *wkhttp.Context) {
		c.checkSign(ctx, secret)
		if ctx.IsAborted() {
			return
		}
		ctx.Next()
	}
}

// 认证中间件 - Ip,Token,菜单,签名
func (c *Context) AuthMiddlewareForIpTokenRbacSign(secret string) wkhttp.HandlerFunc {
	return func(ctx *wkhttp.Context) {

		// Token 校验
		c.checkAuth(ctx, c.Cache(), c.cfg.Cache.TokenCachePrefix)
		if ctx.IsAborted() {
			return
		}

		// IP 白名单
		c.checkAdminIPWhitelist(ctx)
		if ctx.IsAborted() {
			return
		}

		// RBAC 权限
		c.checkAdminPermission(ctx)
		if ctx.IsAborted() {
			return
		}

		//签名
		c.checkSign(ctx, secret)
		if ctx.IsAborted() {
			return
		}

		ctx.Next()
	}
}

// 认证中间件 - Token,签名
func (c *Context) AuthMiddlewareForTokenSign(secret string) wkhttp.HandlerFunc {
	return func(ctx *wkhttp.Context) {

		// Token 校验
		c.checkAuth(ctx, c.Cache(), c.cfg.Cache.TokenCachePrefix)
		if ctx.IsAborted() {
			return
		}

		//签名
		c.checkSign(ctx, secret)
		if ctx.IsAborted() {
			return
		}

		ctx.Next()
	}
}

func (c *Context) GetLoginUID(token string, tokenPrefix string, cache cache.Cache) string {
	uid, err := cache.Get(tokenPrefix + token)
	if err != nil {
		return ""
	}
	return uid
}

func (c *Context) checkAuth(ctx *wkhttp.Context, cache cache.Cache, tokenPrefix string) {
	token := ctx.GetHeader("token")
	if token == "" {
		ctx.Abort()
		ctx.JSON(http.StatusUnauthorized, gin.H{
			"msg": "token不能为空，请先登录！",
		})
		return
	}

	uidAndName := c.GetLoginUID(token, tokenPrefix, cache)
	if strings.TrimSpace(uidAndName) == "" {
		ctx.Abort()
		ctx.JSON(http.StatusUnauthorized, gin.H{
			"msg": "请先登录！",
		})
		return
	}

	uidAndNames := strings.Split(uidAndName, "@")
	if len(uidAndNames) < 2 {
		ctx.Abort()
		ctx.JSON(http.StatusUnauthorized, gin.H{
			"msg": "token有误！",
		})
		return
	}

	ctx.Set("uid", uidAndNames[0])
	ctx.Set("name", uidAndNames[1])
	if len(uidAndNames) > 2 {
		ctx.Set("role", uidAndNames[2])
	}
}

func (c *Context) checkSign(ctx *wkhttp.Context, secret string) {
	req := ctx.Request
	method := req.Method
	path := req.URL.Path

	// =========================
	// 1️ 校验 timestamp
	// =========================
	query := req.URL.Query()

	sign := query.Get("sign")
	timestamp := query.Get("timestamp")

	if sign == "" {
		ctx.JSON(http.StatusUnauthorized, gin.H{"msg": "miss sign"})
		ctx.Abort()
		return
	}

	if timestamp == "" {
		ctx.JSON(http.StatusUnauthorized, gin.H{"msg": "miss timestamp"})
		ctx.Abort()
		return
	}

	ts, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil || math.Abs(float64(time.Now().Unix()-ts)) > 60 {
		ctx.JSON(http.StatusUnauthorized, gin.H{"msg": "timestamp expired"})
		ctx.Abort()
		return
	}

	query.Del("sign")

	// =========================
	// 2️ 处理 query 排序
	// =========================
	keys := make([]string, 0, len(query))
	for k := range query {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var queryBuilder strings.Builder
	for i, k := range keys {
		queryBuilder.WriteString(k)
		queryBuilder.WriteString("=")
		queryBuilder.WriteString(query.Get(k))
		if i < len(keys)-1 {
			queryBuilder.WriteString("&")
		}
	}

	queryString := queryBuilder.String()

	// =========================
	// 3️ 读取 body（关键）
	// =========================
	var bodyBytes []byte
	if method == http.MethodPost || method == http.MethodPut {
		bodyBytes, _ = io.ReadAll(req.Body)
		req.Body = io.NopCloser(bytes.NewBuffer(bodyBytes)) // 还原 body
	}

	// =========================
	// 4️ 生成签名字符串
	// =========================
	data := method + "\n" +
		path + "\n" +
		timestamp + "\n" +
		queryString + "\n" +
		string(bodyBytes)

	expected := HmacSha256(data, secret)

	// =========================
	// 5️ 安全比较
	// =========================
	if !hmac.Equal([]byte(expected), []byte(sign)) {
		ctx.JSON(http.StatusUnauthorized, gin.H{"msg": "invalid sign"})
		ctx.Abort()
		return
	}
}

func (c *Context) checkAdminIPWhitelist(ctx *wkhttp.Context) {
	ip := ctx.ClientIP()
	clientIDStr := ctx.Request.Header.Get("Clientid")
	clientID, _ := strconv.Atoi(clientIDStr)

	uid, exists := ctx.Get("uid")
	if !exists {
		ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"msg": "未找到用户信息"})
		return
	}

	uidStr := uid.(string)

	allowed, err := c.isIPInAdminWhitelist(ip, clientID, uidStr)
	if err != nil {
		fmt.Println("checkAdminIPWhitelist err:", err)
		ctx.Abort()
		ctx.JSON(http.StatusUnauthorized, gin.H{
			"msg": "当前IP不在后台访问白名单中！",
		})
		return
	}

	if !allowed {
		ctx.Abort()
		ctx.JSON(http.StatusUnauthorized, gin.H{
			"msg": "当前IP不在后台访问白名单中！",
		})
		return
	}
}

func (c *Context) checkAdminPermission(ctx *wkhttp.Context) {
	adminUID := ctx.GetLoginUID()

	path := ctx.Request.URL.Path
	method := ctx.Request.Method

	ok, err := c.adminPermission(adminUID, method, path)
	if err != nil {
		ctx.Abort()
		ctx.JSON(http.StatusUnauthorized, gin.H{
			"msg": "无权限访问该接口！",
		})
		return
	}

	if !ok {
		ctx.Abort()
		ctx.JSON(http.StatusUnauthorized, gin.H{
			"msg": "无权限访问该接口！",
		})
		return
	}
}

// isIPInAdminWhitelist 判断IP是否在后台白名单中
func (c *Context) isIPInAdminWhitelist(ip string, clientId int, uid string) (bool, error) {
	fmt.Println("isIPInAdminWhitelist ip:", ip)

	// 1. 基础特权放行
	if ip == "127.0.0.1" || ip == "0.0.0.0" {
		return true, nil
	}

	isOpen := 1

	//超管没有开关限制
	if uid != "admin" {
		query := c.mySQLSession.
			Select("is_whitelist_open").
			From("workplace_app")

		query = query.Where("id = ?", clientId)

		// 执行加载并释放结果
		_, err := query.Limit(1).Load(&isOpen)
		if err != nil {
			return false, err
		}

		if err != nil {
			fmt.Printf("查询白名单开关失败: %v, clientId: %d\n", err, clientId)
		}

		// 开关关闭，直接放行
		if isOpen == 0 {
			return true, nil
		}
	}

	// 3. 校验具体的 IP/网段记录
	var cnt int64
	builder := c.mySQLSession.
		Select("COUNT(1)").
		From("admin_ip_whitelist").
		Where("status = 1")

	// 兼容三种历史数据格式
	ipObj := net.ParseIP(ip)
	if ipObj == nil {
		return false, fmt.Errorf("invalid ip format: %s", ip)
	}

	conds := make([]string, 0, 4)
	args := make([]interface{}, 0, 4)

	if v4 := ipObj.To4(); v4 != nil {
		ip16 := ipObj.To16()

		// 分支1: 历史正常数据，ip=4 mask=4
		conds = append(conds,
			"(LENGTH(ip) = 4 AND LENGTH(mask_binary) = 4 AND (? & mask_binary) = ip)")
		args = append(args, []byte(v4))

		// 分支2: 新数据，ip=16 mask=16
		conds = append(conds,
			"(LENGTH(ip) = 16 AND LENGTH(mask_binary) = 16 AND (? & mask_binary) = ip)")
		args = append(args, []byte(ip16))

		// 分支3: 当前 insert 产生的数据，ip=16 mask=4
		conds = append(conds,
			"(LENGTH(ip) = 16 AND LENGTH(mask_binary) = 4 AND (? & mask_binary) = RIGHT(ip, 4))")
		args = append(args, []byte(v4))
	} else {
		// IPv6 输入，只能匹配 16/16
		conds = append(conds,
			"(LENGTH(ip) = 16 AND LENGTH(mask_binary) = 16 AND (? & mask_binary) = ip)")
		args = append(args, []byte(ipObj.To16()))
	}

	builder = builder.Where("("+strings.Join(conds, " OR ")+")", args...)

	// 非超管且指定了平台时，增加隔离条件,超管只要存在IP即可放行
	if clientId != 0 && uid != "admin" {
		builder = builder.Where("client_id = ?", clientId)
	}

	_, err := builder.Load(&cnt)
	if err != nil {
		return false, err
	}

	return cnt > 0, nil
}

// checkAdminPermission 判断管理员是否有接口访问权限（TODO: 待实现）
func (m *Context) adminPermission(
	adminUID string,
	method string,
	path string,
) (bool, error) {
	// TODO: 后续实现 RBAC 菜单 / API 权限校验
	return true, nil
}

// GetRedisConn GetRedisConn
func (c *Context) GetRedisConn() *redis.Conn {
	return c.NewRedisCache().GetRedisConn()
}

// EventBegin 开启事件
func (c *Context) EventBegin(data *wkevent.Data, tx *dbr.Tx) (int64, error) {
	return c.Event.Begin(data, tx)
}

// EventCommit 提交事件
func (c *Context) EventCommit(eventID int64) {
	c.Event.Commit(eventID)
}

// Schedule 延迟任务
func (c *Context) Schedule(interval time.Duration, f func()) *timingwheel.Timer {
	return c.timingWheel.ScheduleFunc(&everyScheduler{
		Interval: interval,
	}, f)
}

func (c *Context) GetHttpRoute() *wkhttp.WKHttp {
	return c.httpRouter
}

func (c *Context) SetHttpRoute(r *wkhttp.WKHttp) {
	c.httpRouter = r
}

func (c *Context) SetValue(value interface{}, key string) {
	c.valueMap.Store(key, value)
}

func (c *Context) Value(key string) any {
	v, _ := c.valueMap.Load(key)
	return v
}

// OnlineStatus 在线状态
type OnlineStatus struct {
	UID              string // 用户uid
	DeviceFlag       uint8  // 设备标记
	Online           bool   // 是否在线
	SocketID         int64  // 当前设备在wukongim中的在线/离线的socketID
	OnlineCount      int    //在线数量 当前DeviceFlag下的在线设备数量
	TotalOnlineCount int    // 当前用户所有在线设备数量
}

// OnlineStatusListener 在线状态监听
type OnlineStatusListener func(onlineStatusList []OnlineStatus)

var onlinStatusListeners = make([]OnlineStatusListener, 0)

// AddOnlineStatusListener 添加在线状态监听
func (c *Context) AddOnlineStatusListener(listener OnlineStatusListener) {
	onlinStatusListeners = append(onlinStatusListeners, listener)
}

// GetAllOnlineStatusListeners 获取所有在线监听者
func (c *Context) GetAllOnlineStatusListeners() []OnlineStatusListener {
	return onlinStatusListeners
}

// EventCommit 事件提交
type EventCommit func(err error)

// EventListener EventListener
type EventListener func(data []byte, commit EventCommit)

var eventListeners = map[string][]EventListener{}

// AddEventListener  添加事件监听
func (c *Context) AddEventListener(event string, listener EventListener) {
	listeners := eventListeners[event]
	if listeners == nil {
		listeners = make([]EventListener, 0)
	}
	listeners = append(listeners, listener)
	eventListeners[event] = listeners
}

// GetEventListeners 获取某个事件
func (c *Context) GetEventListeners(event string) []EventListener {
	return eventListeners[event]
}

// MessagesListener 消息监听者
type MessagesListener func(messages []*MessageResp)

var messagesListeners = make([]MessagesListener, 0)

// AddMessagesListener 添加消息监听者
func (c *Context) AddMessagesListener(listener MessagesListener) {
	messagesListeners = append(messagesListeners, listener)
}

// NotifyMessagesListeners 通知消息监听者
func (c *Context) NotifyMessagesListeners(messages []*MessageResp) {
	for _, messagesListener := range messagesListeners {
		messagesListener(messages)
	}
}

type everyScheduler struct {
	Interval time.Duration
}

func (s *everyScheduler) Next(prev time.Time) time.Time {
	return prev.Add(s.Interval)
}

func HmacSha256(data, secret string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}
