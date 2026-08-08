package dev.narsaq.speedtester.ui

import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.LinearLayout
import androidx.core.content.ContextCompat
import androidx.recyclerview.widget.DiffUtil
import androidx.recyclerview.widget.ListAdapter
import androidx.recyclerview.widget.RecyclerView
import dev.narsaq.speedtester.R
import dev.narsaq.speedtester.databinding.ItemHeaderBinding
import dev.narsaq.speedtester.databinding.ItemResultBinding
import dev.narsaq.speedtester.model.ConfigType
import dev.narsaq.speedtester.model.ItemStatus
import dev.narsaq.speedtester.model.UiItem
import dev.narsaq.speedtester.util.AsnLookup
import dev.narsaq.speedtester.util.FlagUtil
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch

class ResultsAdapter(
    private val onClick: (UiItem) -> Unit,
    private val onCopy: (UiItem) -> Unit,
    private val scope: CoroutineScope
) : ListAdapter<ResultsAdapter.Row, RecyclerView.ViewHolder>(DIFF) {

    sealed class Row {
        data class Header(val title: String) : Row()
        data class Item(val item: UiItem, val rank: Int) : Row()
    }

    override fun getItemViewType(position: Int): Int = when (getItem(position)) {
        is Row.Header -> VIEW_HEADER
        is Row.Item -> VIEW_ITEM
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): RecyclerView.ViewHolder {
        val inflater = LayoutInflater.from(parent.context)
        return if (viewType == VIEW_HEADER) {
            HeaderVh(ItemHeaderBinding.inflate(inflater, parent, false))
        } else {
            ItemVh(ItemResultBinding.inflate(inflater, parent, false))
        }
    }

    override fun onBindViewHolder(holder: RecyclerView.ViewHolder, position: Int) {
        when (val row = getItem(position)) {
            is Row.Header -> (holder as HeaderVh).bind(row.title)
            is Row.Item -> (holder as ItemVh).bind(row.item, row.rank)
        }
    }

    private inner class HeaderVh(private val b: ItemHeaderBinding) :
        RecyclerView.ViewHolder(b.root) {
        fun bind(title: String) {
            b.tvHeader.text = title
        }
    }

    private inner class ItemVh(private val b: ItemResultBinding) :
        RecyclerView.ViewHolder(b.root) {

        private var flagJob: Job? = null

        fun bind(item: UiItem, rank: Int) {
            val ctx = b.root.context

            flagJob?.cancel()
            b.tvFlag.visibility = View.GONE
            b.tvIsp.text = ""

            b.tvBadge.setText(item.type.labelRes())
            b.tvBadge.background.setTint(
                ContextCompat.getColor(ctx, item.type.badgeColorRes())
            )

            b.tvHost.text = item.host.ifBlank { item.raw.take(60) }
            b.tvPorts.text = ctx.getString(
                R.string.ports_label,
                item.ports.joinToString(", ")
            )
            b.tvReach.text = ""

            if (rank in 1..3 && item.status == ItemStatus.PASSED) {
                b.tvRank.text = ctx.getString(R.string.rank_format, rank)
                b.tvRank.setTextColor(ContextCompat.getColor(ctx, R.color.rank_gold))
                b.tvRank.background.setTint(
                    ContextCompat.getColor(ctx, R.color.rank_gold)
                )
            } else if (rank > 0) {
                b.tvRank.text = ctx.getString(R.string.rank_format, rank)
                b.tvRank.setTextColor(ContextCompat.getColor(ctx, R.color.text_subtle))
                b.tvRank.background.setTint(
                    ContextCompat.getColor(ctx, R.color.md_surface_variant)
                )
            } else {
                b.tvRank.text = ""
            }

            when (item.status) {
                ItemStatus.WAITING -> {
                    b.tvLatency.text = ""
                    b.tvItemStatus.setText(R.string.status_waiting)
                    b.tvItemStatus.setTextColor(ContextCompat.getColor(ctx, R.color.text_subtle))
                    b.tvQuality.visibility = View.GONE
                    b.btnCopyItem.visibility = View.GONE
                    b.qualityBar.visibility = View.GONE
                }

                ItemStatus.TESTING -> {
                    b.tvLatency.text = ""
                    b.tvItemStatus.setText(R.string.status_testing_item)
                    b.tvItemStatus.setTextColor(ContextCompat.getColor(ctx, R.color.text_subtle))
                    b.tvQuality.visibility = View.GONE
                    b.btnCopyItem.visibility = View.GONE
                    b.qualityBar.visibility = View.GONE
                }

                ItemStatus.PASSED -> {
                    b.tvLatency.text = ctx.getString(
                        R.string.latency_ms,
                        item.bestLatencyMs ?: 0L
                    )
                    b.tvLatency.setTextColor(ContextCompat.getColor(ctx, R.color.text_success))
                    b.tvItemStatus.setText(R.string.cd_status_ok)
                    b.tvItemStatus.setTextColor(ContextCompat.getColor(ctx, R.color.text_success))

                    val latency = item.bestLatencyMs ?: Long.MAX_VALUE
                    val (qualityLabel, qualityColor) = when {
                        latency < 100 -> R.string.quality_excellent to R.color.quality_excellent
                        latency < 200 -> R.string.quality_good to R.color.quality_good
                        latency < 350 -> R.string.quality_fair to R.color.quality_fair
                        else -> R.string.quality_slow to R.color.quality_slow
                    }
                    b.tvQuality.text = ctx.getString(qualityLabel)
                    b.tvQuality.visibility = View.VISIBLE
                    b.tvQuality.background.setTint(ContextCompat.getColor(ctx, qualityColor))

                    b.btnCopyItem.visibility = View.VISIBLE
                    b.btnCopyItem.setOnClickListener { onCopy(item) }

                    val best = item.topCandidates.firstOrNull { it.protocolOk }
                        ?: item.topCandidates.firstOrNull()
                    val parts = mutableListOf<String>()
                    best?.let { c ->
                        parts += ctx.getString(R.string.reach_port, c.port)
                    } ?: item.bestPort?.let {
                        parts += ctx.getString(R.string.reach_port, it)
                    }
                    if (best?.protocolVerified == true) {
                        parts += if (best.protocolOk) "E2E ✓" else "E2E ✗"
                    }
                    b.tvReach.text = parts.joinToString(" · ")

                    renderQualityBar(qualityColor, latency)

                    loadFlag(item.bestIp)
                }

                ItemStatus.FAILED -> {
                    b.tvLatency.text = ctx.getString(R.string.speed_na)
                    b.tvLatency.setTextColor(ContextCompat.getColor(ctx, R.color.text_fail))
                    if (item.valid) {
                        b.tvItemStatus.setText(R.string.unreachable)
                    } else {
                        b.tvItemStatus.setText(R.string.invalid_config)
                    }
                    b.tvItemStatus.setTextColor(ContextCompat.getColor(ctx, R.color.text_fail))
                    b.tvQuality.visibility = View.GONE
                    b.btnCopyItem.visibility = View.GONE
                    b.qualityBar.visibility = View.GONE
                }
            }

            b.root.setOnClickListener { onClick(item) }
        }

        private fun renderQualityBar(colorRes: Int, latency: Long) {
            val ctx = b.root.context
            val color = ContextCompat.getColor(ctx, colorRes)
            val filled = when {
                latency < 100 -> 12
                latency < 200 -> 10
                latency < 350 -> 8
                else -> 5
            }
            val segments = b.qualitySegments
            segments.removeAllViews()
            for (i in 0 until 12) {
                val v = View(ctx)
                v.background = ctx.getDrawable(R.drawable.bg_quality_segment)
                if (i < filled) {
                    v.background.setTint(color)
                } else {
                    v.background.setTint(
                        ContextCompat.getColor(ctx, R.color.md_outline_variant)
                    )
                }
                val lp = LinearLayout.LayoutParams(0, 5.dp(ctx), 1f)
                if (i > 0) lp.marginStart = 3.dp(ctx)
                v.layoutParams = lp
                segments.addView(v)
            }
            b.qualityBar.visibility = View.VISIBLE
        }

        private fun Int.dp(ctx: android.content.Context): Int =
            (this * ctx.resources.displayMetrics.density).toInt()

        private fun loadFlag(ip: String?) {
            if (ip.isNullOrBlank()) return
            val cached = AsnLookup.getCached(ip)
            if (cached != null) {
                applyFlag(cached.country, cached.isCloudflare)
                applyIsp(cached)
                return
            }
            val itemId = bindingAdapterPosition
            flagJob = scope.launch {
                val info = AsnLookup.lookup(ip)
                if (bindingAdapterPosition == itemId) {
                    applyFlag(info?.country.orEmpty(), info?.isCloudflare ?: false)
                    applyIsp(info)
                }
            }
        }

        private fun applyIsp(info: AsnLookup.IpInfo?) {
            if (info == null) {
                b.tvIsp.text = ""
                return
            }
            val isp = info.isp.ifBlank { "Cloudflare" }
            val asn = info.asn.ifBlank { "" }.removePrefix("AS")
            b.tvIsp.text = if (asn.isNotBlank()) "$isp · AS$asn" else isp
        }

        private fun applyFlag(country: String, isCloudflare: Boolean) {
            val flag = if (isCloudflare) "" else FlagUtil.countryFlag(country)
            if (flag.isEmpty()) {
                b.tvFlag.visibility = View.GONE
                b.tvFlag.text = ""
            } else {
                b.tvFlag.visibility = View.VISIBLE
                b.tvFlag.text = flag
            }
        }
    }

    companion object {
        private const val VIEW_HEADER = 0
        private const val VIEW_ITEM = 1
        private val MEDALS = arrayOf("\uD83E\uDD47", "\uD83E\uDD48", "\uD83E\uDD49")

        private val DIFF = object : DiffUtil.ItemCallback<Row>() {
            override fun areItemsTheSame(oldItem: Row, newItem: Row): Boolean = when {
                oldItem is Row.Header && newItem is Row.Header -> oldItem.title == newItem.title
                oldItem is Row.Item && newItem is Row.Item -> oldItem.item.id == newItem.item.id
                else -> false
            }

            override fun areContentsTheSame(oldItem: Row, newItem: Row): Boolean =
                oldItem == newItem
        }

        private fun ConfigType.labelRes(): Int = when (this) {
            ConfigType.VLESS -> R.string.type_vless
            ConfigType.VMESS -> R.string.type_vmess
            ConfigType.SHADOWSOCKS -> R.string.type_ss
            ConfigType.TROJAN -> R.string.type_trojan
            ConfigType.PLAIN -> R.string.type_plain
            ConfigType.INVALID -> R.string.type_invalid
        }

        private fun ConfigType.badgeColorRes(): Int = when (this) {
            ConfigType.VLESS -> R.color.badge_vless
            ConfigType.VMESS -> R.color.badge_vmess
            ConfigType.SHADOWSOCKS -> R.color.badge_ss
            ConfigType.TROJAN -> R.color.badge_trojan
            ConfigType.PLAIN -> R.color.badge_plain
            ConfigType.INVALID -> R.color.badge_invalid
        }
    }
}
