import { useEffect, useState } from "react"
import { motion } from "framer-motion"

import {
LineChart,
Line,
XAxis,
YAxis,
Tooltip,
ResponsiveContainer,
PieChart,
Pie,
Cell,
Legend
} from "recharts"

function App() {

const [stats, setStats] = useState({
captured_files: 0,
tampered_files: 0,
integrity_status: "Loading...",
monitoring_status: "Loading..."
})

const [alerts, setAlerts] = useState([])

const [trafficData, setTrafficData] = useState([])

const [threatIntel, setThreatIntel] = useState({
attacker_ip: "Unknown",
packets: 0,
threat_level: "Low"
})

const [evidence, setEvidence] = useState([])

const [protocols, setProtocols] = useState([])

useEffect(() => {

const fetchData = () => {

// Stats
fetch("http://pi5.local:8000/stats")
.then(res => res.json())
.then(data => {
setStats(data)
})

// Alerts
fetch("http://pi5.local:8000/alerts")
.then(res => res.json())
.then(data => {
setAlerts(data)
})

// Traffic
fetch("http://pi5.local:8000/traffic")
.then(res => res.json())
.then(data => {

const currentTime = new Date().toLocaleTimeString()

setTrafficData(prev => [
...prev.slice(-10),
{
time: currentTime,
packets: data.packets || 0
}
])

let level = "Low"

if (data.packets > 500) {
level = "High"
}
else if (data.packets > 200) {
level = "Medium"
}

setThreatIntel({
attacker_ip: data.attacker_ip || "Unknown",
packets: data.packets || 0,
threat_level: level
})

})

// Evidence
fetch("http://pi5.local:8000/evidence")
.then(res => res.json())
.then(data => {
setEvidence(data)
})

// Protocols
fetch("http://pi5.local:8000/protocols")
.then(res => res.json())
.then(data => {
setProtocols(data)
})

}

fetchData()

const interval = setInterval(fetchData, 5000)

return () => clearInterval(interval)

}, [])

const COLORS = [
"#22D3EE",
"#EF4444",
"#FACC15",
"#4ADE80"
]

return (

<div className="bg-gradient-to-br from-[#081120] via-[#0B1020] to-[#111827] min-h-screen text-white flex">

{/* Sidebar */}
<div className="w-64 backdrop-blur-xl bg-white/5 border-r border-white/10 p-6">

<h1 className="text-3xl font-bold text-cyan-400 mb-12">
EdgeSOC
</h1>

<ul className="space-y-6 text-gray-300">

<li className="hover:text-cyan-400 transition cursor-pointer">
Dashboard
</li>

<li className="hover:text-cyan-400 transition cursor-pointer">
Evidence
</li>

<li className="hover:text-cyan-400 transition cursor-pointer">
Alerts
</li>

<li className="hover:text-cyan-400 transition cursor-pointer">
Network
</li>

<li className="hover:text-cyan-400 transition cursor-pointer">
Threat Intel
</li>

<li className="hover:text-cyan-400 transition cursor-pointer">
Settings
</li>

</ul>

</div>

{/* Main */}
<div className="flex-1 p-8">

{/* Header */}
<div className="flex justify-between items-center mb-10">

<div>

<h2 className="text-5xl font-bold mb-2">
SOC Command Center
</h2>

<p className="text-gray-400">
Real-time forensic monitoring & integrity verification
</p>

</div>

{/* Live Indicator */}
<motion.div
animate={{ opacity: [1, 0.5, 1] }}
transition={{ repeat: Infinity, duration: 1.5 }}
className="bg-green-500/20 text-green-400 px-5 py-2 rounded-full border border-green-500/30"
>
● System Active
</motion.div>

</div>

{/* Stats */}
<div className="grid grid-cols-4 gap-6 mb-10">

{[
{
title: "Captured Files",
value: stats.captured_files,
color: "text-cyan-400"
},
{
title: "Tampered Files",
value: stats.tampered_files,
color: "text-red-400"
},
{
title: "Integrity Status",
value: stats.integrity_status,
color: "text-green-400"
},
{
title: "Live Monitoring",
value: stats.monitoring_status,
color: "text-yellow-400"
}

].map((card, index) => (

<motion.div
key={index}
whileHover={{ scale: 1.03 }}
className="backdrop-blur-xl bg-white/5 rounded-2xl p-6 border border-white/10 shadow-lg"
>

<p className="text-gray-400">
{card.title}
</p>

<h3 className={`text-4xl font-bold mt-4 ${card.color}`}>
{card.value}
</h3>

</motion.div>

))}

</div>

{/* Traffic + Threat */}
<div className="grid grid-cols-3 gap-6 mb-10">

{/* Traffic Chart */}
<motion.div
whileHover={{ scale: 1.01 }}
className="col-span-2 backdrop-blur-xl bg-white/5 rounded-2xl p-6 border border-white/10 shadow-lg"
>

<h3 className="text-2xl font-bold mb-6">
Live Network Traffic
</h3>

<div className="h-80">

<ResponsiveContainer width="100%" height="100%">

<LineChart data={trafficData}>

<XAxis dataKey="time" stroke="#9CA3AF" />

<YAxis stroke="#9CA3AF" />

<Tooltip />

<Line
type="monotone"
dataKey="packets"
stroke="#22D3EE"
strokeWidth={3}
/>

</LineChart>

</ResponsiveContainer>

</div>

</motion.div>

{/* Threat Intel */}
<motion.div
whileHover={{ scale: 1.01 }}
className="backdrop-blur-xl bg-white/5 rounded-2xl p-6 border border-white/10 shadow-lg"
>

<h3 className="text-2xl font-bold mb-6 text-red-400">
Threat Intel
</h3>

<div className="space-y-4">

<div className="bg-black/20 p-4 rounded-xl">

<p className="text-sm text-gray-400">
Top Attacker IP
</p>

<p className="text-lg font-bold text-red-400 mt-2">
{threatIntel.attacker_ip}
</p>

</div>

<div className="bg-black/20 p-4 rounded-xl">

<p className="text-sm text-gray-400">
Threat Level
</p>

<p className="text-lg font-bold text-yellow-400 mt-2">
{threatIntel.threat_level}
</p>

</div>

<div className="bg-black/20 p-4 rounded-xl">

<p className="text-sm text-gray-400">
Packets Captured
</p>

<p className="text-lg font-bold text-cyan-400 mt-2">
{threatIntel.packets}
</p>

</div>

</div>

</motion.div>

</div>

{/* Protocol Analytics */}
<motion.div
whileHover={{ scale: 1.005 }}
className="backdrop-blur-xl bg-white/5 rounded-2xl p-6 border border-white/10 shadow-lg mb-10"
>

<h3 className="text-2xl font-bold mb-6 text-cyan-400">
Protocol Distribution
</h3>

<div className="h-96">

<ResponsiveContainer width="100%" height="100%">

<PieChart>

<Pie
data={protocols}
cx="50%"
cy="50%"
outerRadius={120}
dataKey="value"
label
>

{protocols.map((entry, index) => (

<Cell
key={`cell-${index}`}
fill={COLORS[index % COLORS.length]}
/>

))}

</Pie>

<Tooltip />

<Legend />

</PieChart>

</ResponsiveContainer>

</div>

</motion.div>

{/* Alerts */}
<motion.div
whileHover={{ scale: 1.005 }}
className="backdrop-blur-xl bg-white/5 rounded-2xl p-6 border border-white/10 shadow-lg mb-10"
>

<h3 className="text-2xl font-bold mb-6 text-red-400">
Live Alert Feed
</h3>

<div className="space-y-4 max-h-96 overflow-y-auto">

{alerts.length > 0 ? (

alerts.map((alert, index) => (

<motion.div
initial={{ opacity: 0, y: 10 }}
animate={{ opacity: 1, y: 0 }}
transition={{ duration: 0.3 }}
key={index}
className="bg-black/20 p-4 rounded-xl border border-white/10"
>
{alert}
</motion.div>

))

) : (

<div className="text-gray-400">
No active alerts
</div>

)}

</div>

</motion.div>

{/* Evidence */}
<motion.div
whileHover={{ scale: 1.005 }}
className="backdrop-blur-xl bg-white/5 rounded-2xl p-6 border border-white/10 shadow-lg"
>

<h3 className="text-2xl font-bold mb-6 text-cyan-400">
Evidence Explorer
</h3>

<div className="overflow-x-auto">

<table className="w-full text-left">

<thead>

<tr className="border-b border-white/10 text-gray-400">

<th className="pb-4">Filename</th>
<th className="pb-4">SHA-256 Hash</th>
<th className="pb-4">Status</th>

</tr>

</thead>

<tbody>

{evidence.length > 0 ? (

evidence.map((item, index) => (

<tr
key={index}
className="border-b border-white/5 hover:bg-white/5 transition"
>

<td className="py-4">
{item.filename}
</td>

<td className="py-4 text-cyan-400">
{item.hash}
</td>

<td className="py-4">

<span className="bg-green-500/20 text-green-400 px-3 py-1 rounded-full text-sm border border-green-500/30">
Verified
</span>

</td>

</tr>

))

) : (

<tr>

<td className="py-4 text-gray-400">
No evidence found
</td>

</tr>

)}

</tbody>

</table>

</div>

</motion.div>

</div>

</div>

)
}

export default App
