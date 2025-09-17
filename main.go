package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"sync"
	"syscall"
	"time"
	"github.com/joho/godotenv"
	"github.com/fatih/color"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/jedib0t/go-pretty/v6/table"
	"golang.org/x/term"
	bolt "go.etcd.io/bbolt"
)

// ----------------------------- Data Types -----------------------------

// ConnectionStats tracks per-IP activity and baselines
type ConnectionStats struct {
	IP                string
	Connections       int
	Packets           int
	Bytes             int
	AvgConnections    float64
	AvgPackets        float64
	AvgPacketSize     float64
	LastUpdate        time.Time
	AnomalyDetected   bool
	PacketSpikeCount  int
	ConnectionHistory []int
	PacketHistory     []int
	ZConn             float64
	ZPackets          float64
	Danger            float64
}

// Detector holds global monitoring and persistence state
type Detector struct {
	// live stats
	IPs          map[string]*ConnectionStats
	SamplePeriod time.Duration
	Alpha        float64
	AlertDelay   int

	// capture aggregation
	mu       sync.Mutex
	interval map[string]*intervalCounter

	// global baselines
	Global         GlobalStats
	ddosActive     bool
	globalSpikeCnt int
	prevDdosActive bool

	// warm-up and detection gating
	samples              int
	MinSamplesForDetect  int
	MinPacketsForDetect  int
	MinActiveIPsForCheck int

	// output control
	MaxActivityRows int
	MaxThreatRows   int
	NoTTYRate       int
	tickCount       int

	// alerting
	WebhookURL    string
	AlertCooldown time.Duration
	lastGlobal    time.Time

	// persistence
	DBPath     string
	DBSaveEvery time.Duration
	db         *bolt.DB
}

type intervalCounter struct {
	connections int // TCP SYNs (no ACK) counted as "new connections"
	packets     int
	bytes       int
}

type GlobalStats struct {
	AvgPackets      float64
	AvgUniqueIPs    float64
	PacketHistory   []int
	UniqueIPHistory []int
	MaxHistory      int
}

// persisted models
type persistedIP struct {
	AvgConnections float64 `json:"avg_conn"`
	AvgPackets     float64 `json:"avg_pkts"`
	AvgPacketSize  float64 `json:"avg_pkt_sz"`
	ConnHist       []int   `json:"conn_hist"`
	PktHist        []int   `json:"pkt_hist"`
}

type persistedGlobal struct {
	AvgPackets      float64 `json:"avg_pkts"`
	AvgUniqueIPs    float64 `json:"avg_uips"`
	PacketHistory   []int   `json:"pkt_hist"`
	UniqueIPHistory []int   `json:"uip_hist"`
	MaxHistory      int     `json:"max_hist"`
}

// ----------------------------- Initialization -----------------------------

func NewDetector() *Detector {
	return &Detector{
		IPs:                   make(map[string]*ConnectionStats),
		SamplePeriod:          1 * time.Second,
		Alpha:                 0.3,
		AlertDelay:            3,
		interval:              make(map[string]*intervalCounter),
		Global:                GlobalStats{MaxHistory: 120},
		MinSamplesForDetect:   15,      // warm-up intervals before any detection
		MinPacketsForDetect:   2000,    // global volume gate for detection
		MinActiveIPsForCheck:  5,       // skip global logic if fewer IPs active
		MaxActivityRows:       30,      // table 1 cap
		MaxThreatRows:         20,      // table 2 cap
		NoTTYRate:             5,       // throttle non-TTY printing
		WebhookURL:            os.Getenv("DISCORD_WEBHOOK"),
		AlertCooldown:         30 * time.Second,
		DBPath:                "ddos.db",
		DBSaveEvery:           10 * time.Second,
	}
}

// ----------------------------- Capture -----------------------------

func (d *Detector) startCaptureAll() error {
	devs, err := pcap.FindAllDevs()
	if err != nil {
		return fmt.Errorf("pcap find devices: %w", err)
	}
	if len(devs) == 0 {
		return fmt.Errorf("no interfaces found (pcap)")
	}
	for _, dev := range devs {
		if dev.Name == "" {
			continue
		}
		go d.captureLoop(dev.Name)
	}
	return nil
}

func (d *Detector) captureLoop(iface string) {
	handle, err := pcap.OpenLive(iface, 65535, true, pcap.BlockForever)
	if err != nil {
		log.Printf("capture(%s): open failed: %v", iface, err)
		return
	}
	defer handle.Close()
	log.Printf("capture started on %s", iface)

	src := gopacket.NewPacketSource(handle, handle.LinkType())
	for pkt := range src.Packets() {
		var srcIP string
		if ip4 := pkt.Layer(layers.LayerTypeIPv4); ip4 != nil {
			srcIP = ip4.(*layers.IPv4).SrcIP.String()
		} else if ip6 := pkt.Layer(layers.LayerTypeIPv6); ip6 != nil {
			srcIP = ip6.(*layers.IPv6).SrcIP.String()
		} else {
			continue
		}

		isConn := false
		if tcpL := pkt.Layer(layers.LayerTypeTCP); tcpL != nil {
			tcp := tcpL.(*layers.TCP)
			if tcp.SYN && !tcp.ACK {
				isConn = true
			}
		}

		ci := pkt.Metadata().CaptureInfo

		d.mu.Lock()
		ctr := d.interval[srcIP]
		if ctr == nil {
			ctr = &intervalCounter{}
			d.interval[srcIP] = ctr
		}
		ctr.packets++
		ctr.bytes += ci.Length
		if isConn {
			ctr.connections++
		}
		d.mu.Unlock()
	}
}

// ----------------------------- Stats Update -----------------------------

// updateIP updates per-IP stats; baselines train only when 'train' is true
func (d *Detector) updateIP(ip string, connections, packets, bytes int, train bool) {
	now := time.Now()
	stat, exists := d.IPs[ip]
	if !exists {
		stat = &ConnectionStats{IP: ip, LastUpdate: now}
		d.IPs[ip] = stat
	}
	// Baseline training (EWMA)
	if train {
		stat.AvgConnections = d.Alpha*float64(connections) + (1-d.Alpha)*stat.AvgConnections
		stat.AvgPackets = d.Alpha*float64(packets) + (1-d.Alpha)*stat.AvgPackets
		ps := 0.0
		if packets > 0 {
			ps = float64(bytes) / float64(packets)
		}
		stat.AvgPacketSize = d.Alpha*ps + (1-d.Alpha)*stat.AvgPacketSize
	}

	stat.Connections = connections
	stat.Packets = packets
	stat.Bytes = bytes
	stat.LastUpdate = now

	// History for z-scores
	stat.ConnectionHistory = append(stat.ConnectionHistory, connections)
	if len(stat.ConnectionHistory) > 60 {
		stat.ConnectionHistory = stat.ConnectionHistory[1:]
	}
	stat.PacketHistory = append(stat.PacketHistory, packets)
	if len(stat.PacketHistory) > 60 {
		stat.PacketHistory = stat.PacketHistory[1:]
	}

	// Compute z-scores
	sdConn := stdDev(stat.ConnectionHistory)
	sdPkt := stdDev(stat.PacketHistory)
	if sdConn > 0 {
		stat.ZConn = (float64(connections) - stat.AvgConnections) / sdConn
	} else {
		stat.ZConn = 0
	}
	if sdPkt > 0 {
		stat.ZPackets = (float64(packets) - stat.AvgPackets) / sdPkt
	} else {
		stat.ZPackets = 0
	}

	// Per-IP anomaly flags (gated by warm-up via caller)
	stat.AnomalyDetected = false
	connThreshold := stat.AvgConnections + 3*sdConn
	if float64(connections) > connThreshold && connections > 20 {
		stat.AnomalyDetected = true
	}
	packetThreshold := stat.AvgPackets + 3*sdPkt
	if float64(packets) > packetThreshold && packets > 50 {
		stat.PacketSpikeCount++
	} else {
		stat.PacketSpikeCount = 0
	}
	if stat.PacketSpikeCount >= d.AlertDelay {
		stat.AnomalyDetected = true
	}

	// Danger score
	zp := math.Max(0, stat.ZPackets)
	zc := math.Max(0, stat.ZConn)
	boost := 0.0
	if d.ddosActive {
		boost = 1.0
	}
	stat.Danger = 0.6*zp + 0.4*zc + boost
}

func (d *Detector) updateGlobal(totalPackets int, uniqueIPs int, train bool) {
	if train {
		d.Global.AvgPackets = d.Alpha*float64(totalPackets) + (1-d.Alpha)*d.Global.AvgPackets
		d.Global.AvgUniqueIPs = d.Alpha*float64(uniqueIPs) + (1-d.Alpha)*d.Global.AvgUniqueIPs
	}
	d.Global.PacketHistory = append(d.Global.PacketHistory, totalPackets)
	if len(d.Global.PacketHistory) > d.Global.MaxHistory {
		d.Global.PacketHistory = d.Global.PacketHistory[1:]
	}
	d.Global.UniqueIPHistory = append(d.Global.UniqueIPHistory, uniqueIPs)
	if len(d.Global.UniqueIPHistory) > d.Global.MaxHistory {
		d.Global.UniqueIPHistory = d.Global.UniqueIPHistory[1:]
	}
}

// evaluateGlobalDdos decides global DDoS state with consecutive confirmation and warm-up gating
func (d *Detector) evaluateGlobalDdos(totalPackets int, offenders int, activeIPs int) {
	// Warm-up and volume gates to avoid early false positives
	if d.samples < d.MinSamplesForDetect || totalPackets < d.MinPacketsForDetect || activeIPs < d.MinActiveIPsForCheck {
		d.globalSpikeCnt = 0
		d.ddosActive = false
		return
	}

	pktSD := stdDev(d.Global.PacketHistory)
	avgPkts := d.Global.AvgPackets
	globalSpike := false

	// Condition A: packets 3x EWMA or > EWMA + 3*SD
	if (avgPkts > 0 && float64(totalPackets) > 3*avgPkts) || (pktSD > 0 && float64(totalPackets) > avgPkts+3*pktSD) {
		globalSpike = true
	}

	// Condition B: many concurrent offenders
	if activeIPs > 0 {
		ratio := float64(offenders) / float64(activeIPs)
		if offenders >= 10 && ratio >= 0.3 {
			globalSpike = true
		}
	}

	// Stabilize with consecutive confirmations
	if globalSpike {
		d.globalSpikeCnt++
	} else if d.globalSpikeCnt > 0 {
		d.globalSpikeCnt--
	}

	// Enter/exit state with hysteresis
	if d.globalSpikeCnt >= d.AlertDelay {
		d.ddosActive = true
	} else if d.globalSpikeCnt == 0 {
		d.ddosActive = false
	}
}

// ----------------------------- Rendering -----------------------------

func limitRows[T any](in []T, n int) []T {
	if n <= 0 || len(in) <= n {
		return in
	}
	return in[:n]
}

func (d *Detector) displayTables() {
	stdoutFD := int(os.Stdout.Fd())
	isTTY := term.IsTerminal(stdoutFD)

	perTableRows := 0
	if isTTY {
		if _, h, err := term.GetSize(stdoutFD); err == nil && h > 10 {
			usable := h - 8
			if usable < 10 {
				usable = 10
			}
			perTableRows = usable / 2
		}
		fmt.Print("\033[2J\033[H")
	} else {
		d.tickCount++
		if d.tickCount%d.NoTTYRate != 0 {
			return
		}
	}

	// Gather and sort data
	stats1 := make([]*ConnectionStats, 0, len(d.IPs))
	for _, s := range d.IPs {
		stats1 = append(stats1, s)
	}
	sort.Slice(stats1, func(i, j int) bool {
		if stats1[i].Packets == stats1[j].Packets {
			return stats1[i].Connections > stats1[j].Connections
		}
		return stats1[i].Packets > stats1[j].Packets
	})
	stats2 := make([]*ConnectionStats, 0, len(d.IPs))
	for _, s := range d.IPs {
		stats2 = append(stats2, s)
	}
	sort.Slice(stats2, func(i, j int) bool {
		if stats2[i].Danger == stats2[j].Danger {
			return stats2[i].Packets > stats2[j].Packets
		}
		return stats2[i].Danger > stats2[j].Danger
	})

	// Caps
	cap1 := d.MaxActivityRows
	cap2 := d.MaxThreatRows
	if perTableRows > 0 {
		if cap1 == 0 || perTableRows < cap1 {
			cap1 = perTableRows
		}
		if cap2 == 0 || perTableRows < cap2 {
			cap2 = perTableRows
		}
		if cap1 < 5 {
			cap1 = 5
		}
		if cap2 < 5 {
			cap2 = 5
		}
	}
	stats1 = limitRows(stats1, cap1)
	stats2 = limitRows(stats2, cap2)

	// Table 1: activity
	t1 := table.NewWriter()
	t1.SetStyle(table.StyleColoredBright)
	t1.AppendHeader(table.Row{"IP", "Conn", "AvgConn", "Pkts", "AvgPktSz", "Status"})
	for _, s := range stats1 {
		status := color.GreenString("NORMAL")
		if d.samples < d.MinSamplesForDetect {
			status = color.YellowString("WARMUP")
		} else if s.AnomalyDetected && !d.ddosActive {
			status = color.YellowString("WARN")
		} else if s.AnomalyDetected && d.ddosActive {
			status = color.RedString("ALERT")
		}
		t1.AppendRow(table.Row{
			s.IP,
			s.Connections,
			fmt.Sprintf("%.1f", s.AvgConnections),
			s.Packets,
			fmt.Sprintf("%.1f", s.AvgPacketSize),
			status,
		})
	}
	fmt.Println("Per-IP Activity (top)", len(stats1))
	fmt.Println(t1.Render())

	// Table 2: threats
	t2 := table.NewWriter()
	t2.SetStyle(table.StyleColoredBright)
	t2.AppendHeader(table.Row{"IP", "Pkts", "Conns", "Zpkts", "Zconn", "Danger", "Flag"})
	for _, s := range stats2 {
		flag := ""
		if d.ddosActive && s.AnomalyDetected {
			flag = color.RedString("HOT")
		} else if s.AnomalyDetected {
			flag = color.YellowString("SUS")
		}
		t2.AppendRow(table.Row{
			s.IP,
			s.Packets,
			s.Connections,
			fmt.Sprintf("%.2f", s.ZPackets),
			fmt.Sprintf("%.2f", s.ZConn),
			fmt.Sprintf("%.2f", s.Danger),
			flag,
		})
	}
	title := "Top Threats (sorted by danger)"
	if d.ddosActive {
		title = color.RedString("Top Threats (GLOBAL DDoS DETECTED)")
	} else if d.samples < d.MinSamplesForDetect {
		title = color.YellowString("Top Threats (WARM-UP)")
	}
	fmt.Println(title, "(top)", len(stats2))
	fmt.Println(t2.Render())
}

// ----------------------------- Alerts -----------------------------

type discordEmbed struct {
	Title       string       `json:"title,omitempty"`
	Description string       `json:"description,omitempty"`
	Color       int          `json:"color,omitempty"`
	Fields      []embedField `json:"fields,omitempty"`
	Timestamp   string       `json:"timestamp,omitempty"`
}
type embedField struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

func (d *Detector) sendDiscordAlertTop(totalPackets int, offenders []*ConnectionStats) {
	if d.WebhookURL == "" {
		return
	}
	now := time.Now()
	if now.Sub(d.lastGlobal) < d.AlertCooldown {
		return
	}
	d.lastGlobal = now

	topN := 5
	if len(offenders) < topN {
		topN = len(offenders)
	}
	lines := ""
	for i := 0; i < topN; i++ {
		s := offenders[i]
		lines += fmt.Sprintf("• %s pkts=%d z=%.2f danger=%.2f\n", s.IP, s.Packets, s.ZPackets, s.Danger)
	}

	embed := discordEmbed{
		Title:       "DDoS ALERT",
		Description: fmt.Sprintf("Global spike detected. total_pkts=%d avg_pkts=%.0f offenders=%d", totalPackets, d.Global.AvgPackets, len(offenders)),
		Color:       0xFF0000,
		Fields: []embedField{
			{Name: "Top Offenders", Value: lines},
		},
		Timestamp: time.Now().Format(time.RFC3339),
	}
	payload := map[string]interface{}{
		"content": "",
		"embeds":  []discordEmbed{embed},
	}
	_ = d.postDiscord(payload)
}

func (d *Detector) postDiscord(body interface{}) error {
	b, _ := json.Marshal(body)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.WebhookURL, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook status %d", resp.StatusCode)
	}
	return nil
}

// ----------------------------- Persistence -----------------------------

func (d *Detector) openDB() error {
	db, err := bolt.Open(d.DBPath, 0600, &bolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		return err
	}
	d.db = db
	return d.db.Update(func(tx *bolt.Tx) error {
		if _, err := tx.CreateBucketIfNotExists([]byte("perip")); err != nil {
			return err
		}
		if _, err := tx.CreateBucketIfNotExists([]byte("global")); err != nil {
			return err
		}
		if _, err := tx.CreateBucketIfNotExists([]byte("meta")); err != nil {
			return err
		}
		return nil
	})
}

func (d *Detector) loadDB() error {
	if d.db == nil {
		return fmt.Errorf("db not open")
	}
	return d.db.View(func(tx *bolt.Tx) error {
		// global
		gb := tx.Bucket([]byte("global"))
		if gb != nil {
			if raw := gb.Get([]byte("stats")); raw != nil {
				var pg persistedGlobal
				if err := json.Unmarshal(raw, &pg); err == nil {
					d.Global.AvgPackets = pg.AvgPackets
					d.Global.AvgUniqueIPs = pg.AvgUniqueIPs
					d.Global.PacketHistory = append([]int(nil), pg.PacketHistory...)
					d.Global.UniqueIPHistory = append([]int(nil), pg.UniqueIPHistory...)
					if pg.MaxHistory > 0 {
						d.Global.MaxHistory = pg.MaxHistory
					}
				}
			}
		}
		// per-ip
		pb := tx.Bucket([]byte("perip"))
		if pb != nil {
			_ = pb.ForEach(func(k, v []byte) error {
				var pi persistedIP
				if err := json.Unmarshal(v, &pi); err == nil {
					ip := string(k)
					d.IPs[ip] = &ConnectionStats{
						IP:                ip,
						AvgConnections:    pi.AvgConnections,
						AvgPackets:        pi.AvgPackets,
						AvgPacketSize:     pi.AvgPacketSize,
						ConnectionHistory: append([]int(nil), pi.ConnHist...),
						PacketHistory:     append([]int(nil), pi.PktHist...),
						LastUpdate:        time.Now(),
					}
				}
				return nil
			})
		}
		return nil
	})
}

func (d *Detector) saveSnapshot() error {
	if d.db == nil {
		return fmt.Errorf("db not open")
	}
	// Build snapshot without holding d.mu (we only read from d.IPs map here)
	type kv struct {
		key string
		val []byte
	}
	perIP := make([]kv, 0, len(d.IPs))
	for ip, s := range d.IPs {
		pi := persistedIP{
			AvgConnections: s.AvgConnections,
			AvgPackets:     s.AvgPackets,
			AvgPacketSize:  s.AvgPacketSize,
			ConnHist:       trimInts(s.ConnectionHistory, 60),
			PktHist:        trimInts(s.PacketHistory, 60),
		}
		b, _ := json.Marshal(pi)
		perIP = append(perIP, kv{key: ip, val: b})
	}
	pg := persistedGlobal{
		AvgPackets:      d.Global.AvgPackets,
		AvgUniqueIPs:    d.Global.AvgUniqueIPs,
		PacketHistory:   trimInts(d.Global.PacketHistory, d.Global.MaxHistory),
		UniqueIPHistory: trimInts(d.Global.UniqueIPHistory, d.Global.MaxHistory),
		MaxHistory:      d.Global.MaxHistory,
	}
	gb, _ := json.Marshal(pg)

	return d.db.Update(func(tx *bolt.Tx) error {
		pb := tx.Bucket([]byte("perip"))
		gbkt := tx.Bucket([]byte("global"))
		if pb == nil || gbkt == nil {
			return fmt.Errorf("buckets missing")
		}
		for _, x := range perIP {
			if err := pb.Put([]byte(x.key), x.val); err != nil {
				return err
			}
		}
		if err := gbkt.Put([]byte("stats"), gb); err != nil {
			return err
		}
		return nil
	})
}

func trimInts(in []int, max int) []int {
	if max <= 0 || len(in) <= max {
		return append([]int(nil), in...)
	}
	return append([]int(nil), in[len(in)-max:]...)
}

// ----------------------------- Main Loop -----------------------------

func (d *Detector) monitor() {
	// periodic DB saver
	saveTicker := time.NewTicker(d.DBSaveEvery)
	defer saveTicker.Stop()

	ticker := time.NewTicker(d.SamplePeriod)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			d.tick()
		case <-saveTicker.C:
			if err := d.saveSnapshot(); err != nil {
				log.Printf("db save: %v", err)
			}
		}
	}
}

func (d *Detector) tick() {
	// Snapshot interval and reset
	snap := make(map[string]intervalCounter)
	d.mu.Lock()
	for ip, ctr := range d.interval {
		snap[ip] = *ctr
	}
	d.interval = make(map[string]*intervalCounter)
	d.mu.Unlock()

	totalPackets := 0
	for _, ctr := range snap {
		totalPackets += ctr.packets
	}
	activeIPs := len(snap)

	// Increment sample count for warm-up gating
	d.samples++

	// Train when not under DDoS; always train during warm-up
	train := (d.samples < d.MinSamplesForDetect) || !d.ddosActive

	// Update per-IP
	for ip, ctr := range snap {
		d.updateIP(ip, ctr.connections, ctr.packets, ctr.bytes, train)
	}
	// Update global
	d.updateGlobal(totalPackets, activeIPs, train)

	// Build offenders set (warm-up: don't flag per-IP)
	offenders := make([]*ConnectionStats, 0, len(d.IPs))
	if d.samples >= d.MinSamplesForDetect {
		for _, s := range d.IPs {
			zpkt := s.ZPackets
			if (s.AvgPackets > 0 && float64(s.Packets) > 3*s.AvgPackets) || zpkt > 3 {
				if s.Packets > 100 {
					offenders = append(offenders, s)
				}
			}
		}
	}
	sort.Slice(offenders, func(i, j int) bool { return offenders[i].Danger > offenders[j].Danger })

	// Evaluate global DDoS
	d.prevDdosActive = d.ddosActive
	d.evaluateGlobalDdos(totalPackets, len(offenders), activeIPs)

	// On rising edge, alert
	if d.ddosActive && !d.prevDdosActive {
		d.sendDiscordAlertTop(totalPackets, offenders)
	}

	// Render
	d.displayTables()

	// Cleanup stale IPs
	now := time.Now()
	for ip, s := range d.IPs {
		if now.Sub(s.LastUpdate) > 10*time.Minute {
			delete(d.IPs, ip)
		}
	}
}

// ----------------------------- Utils -----------------------------

func stdDev(values []int) float64 {
	if len(values) == 0 {
		return 0
	}
	mean := 0.0
	for _, v := range values {
		mean += float64(v)
	}
	mean /= float64(len(values))
	variance := 0.0
	for _, v := range values {
		diff := float64(v) - mean
		variance += diff * diff
	}
	variance /= float64(len(values))
	return math.Sqrt(variance)
}

// ----------------------------- Entrypoint -----------------------------

func main() {
	godotenv.Load();
	d := NewDetector()

	// DB open + load
	if err := d.openDB(); err != nil {
		log.Fatalf("open db: %v", err)
	}
	defer d.db.Close()
	if err := d.loadDB(); err != nil {
		log.Printf("load db: %v", err)
	}

	// Start capture
	log.Println("Starting live DDoS monitoring (all interfaces, all ports)...")
	if err := d.startCaptureAll(); err != nil {
		log.Fatalf("start capture failed: %v", err)
	}

	// Signals
	sigC := make(chan os.Signal, 1)
	signal.Notify(sigC, syscall.SIGINT, syscall.SIGTERM)

	// Monitor
	go d.monitor()

	<-sigC
	log.Println("Shutting down...")
	_ = d.saveSnapshot()
}
