package dev.narsaq.speedtester.ui

import android.view.LayoutInflater
import android.view.ViewGroup
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

class ResultsAdapter(private val onClick: (UiItem) -> Unit) :
    ListAdapter<ResultsAdapter.Row, RecyclerView.ViewHolder>(DIFF) {

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

        fun bind(item: UiItem, rank: Int) {
            val ctx = b.root.context

            b.tvBadge.setText(item.type.labelRes())
            b.tvBadge.background.setTint(
                ContextCompat.getColor(ctx, item.type.badgeColorRes())
            )

            b.tvHost.text = item.host.ifBlank { item.raw.take(60) }
            b.tvPorts.text = ctx.getString(
                R.string.ports_label,
                item.ports.joinToString(", ")
            )

            if (rank in 1..3 && item.status == ItemStatus.PASSED) {
                b.tvRank.text = MEDALS[rank - 1]
                b.tvRank.setTextColor(ContextCompat.getColor(ctx, R.color.rank_gold))
            } else if (rank > 0) {
                b.tvRank.text = ctx.getString(R.string.rank_format, rank)
                b.tvRank.setTextColor(ContextCompat.getColor(ctx, R.color.text_subtle))
            } else {
                b.tvRank.text = ""
            }

            when (item.status) {
                ItemStatus.WAITING -> {
                    b.tvLatency.text = ""
                    b.tvSpeed.text = ""
                    b.tvItemStatus.setText(R.string.status_waiting)
                    b.tvItemStatus.setTextColor(ContextCompat.getColor(ctx, R.color.text_subtle))
                }

                ItemStatus.TESTING -> {
                    b.tvLatency.text = ""
                    b.tvSpeed.text = ""
                    b.tvItemStatus.setText(R.string.status_testing_item)
                    b.tvItemStatus.setTextColor(ContextCompat.getColor(ctx, R.color.text_subtle))
                }

                ItemStatus.PASSED -> {
                    b.tvLatency.text = ctx.getString(
                        R.string.latency_ms,
                        item.bestLatencyMs ?: 0L
                    )
                    b.tvLatency.setTextColor(ContextCompat.getColor(ctx, R.color.text_success))
                    b.tvSpeed.text = ctx.getString(R.string.tcp_reachable)
                    b.tvItemStatus.setText(R.string.cd_status_ok)
                    b.tvItemStatus.setTextColor(ContextCompat.getColor(ctx, R.color.text_success))
                }

                ItemStatus.FAILED -> {
                    b.tvLatency.text = ctx.getString(R.string.speed_na)
                    b.tvLatency.setTextColor(ContextCompat.getColor(ctx, R.color.text_fail))
                    b.tvSpeed.text = ""
                    if (item.valid) {
                        b.tvItemStatus.setText(R.string.unreachable)
                    } else {
                        b.tvItemStatus.setText(R.string.invalid_config)
                    }
                    b.tvItemStatus.setTextColor(ContextCompat.getColor(ctx, R.color.text_fail))
                }
            }

            b.root.setOnClickListener { onClick(item) }
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
