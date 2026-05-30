import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns

# 设置中文字体和样式
plt.rcParams['font.sans-serif'] = ['SimHei', 'DejaVu Sans', 'Arial']
plt.rcParams['axes.unicode_minus'] = False
sns.set_style("whitegrid")

# 固定的数据 - 模拟原图的数据分布
np.random.seed(42)  # 固定随机种子确保数据一致

# 温度点
temperatures = [0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0]

# 为每个温度点生成固定的准确率数据
data_dict = {
    0: [94.0, 94.2, 94.5, 94.6, 94.8, 95.0, 95.2, 94.9, 94.7, 94.3, 95.1, 94.4],
    0.1: [94.1, 94.3, 94.4, 94.5, 94.6, 94.2, 94.8, 95.3, 94.0, 94.7],  # 包含一个异常值
    0.2: [93.8, 94.2, 94.6, 94.9, 95.1, 95.0, 94.7, 94.4, 95.8, 95.2, 94.5],  # 包含异常值
    0.3: [94.0, 94.2, 94.5, 94.8, 95.0, 96.7, 94.9, 95.1, 94.6, 94.7, 95.2],  # 包含异常值
    0.4: [96.0, 96.2, 96.5, 96.8, 97.0, 96.9, 97.2, 96.7, 96.4, 96.1, 96.6],
    0.5: [96.0, 96.3, 96.8, 97.0, 97.1, 96.9, 97.2, 96.5, 96.7, 96.4],
    0.6: [95.2, 95.5, 95.8, 96.2, 96.5, 96.8, 97.1, 96.0, 95.7, 96.3, 95.9],
    0.7: [95.0, 95.3, 95.6, 95.9, 96.2, 96.8, 97.0, 95.8, 95.5, 96.1, 95.7],
    0.8: [93.6, 94.0, 94.3, 94.6, 94.9, 95.2, 96.3, 97.0, 94.2, 94.8, 94.5],
    0.9: [94.0, 94.3, 94.6, 94.9, 95.2, 95.0, 94.7, 94.4, 95.3, 94.8],
    1.0: [93.0, 93.5, 93.8, 94.1, 94.4, 94.7, 95.0, 96.0, 94.2, 93.9, 94.6]
}

# 准备绘图数据
plot_data = []
for temp in temperatures:
    for accuracy in data_dict[temp]:
        plot_data.append({'Temperature': temp, 'Accuracy': accuracy})

df = pd.DataFrame(plot_data)

# 创建图形
fig, ax = plt.subplots(figsize=(12, 8))

# 创建箱线图
box_plot = ax.boxplot([data_dict[temp] for temp in temperatures],
                      positions=temperatures,
                      widths=0.06,
                      patch_artist=True,
                      showfliers=True,  # 显示异常值
                      flierprops=dict(marker='o', markerfacecolor='white',
                                    markeredgecolor='black', markersize=6, alpha=0.8))

# 设置箱线图颜色
colors = ['lightblue'] * len(temperatures)
for patch, color in zip(box_plot['boxes'], colors):
    patch.set_facecolor(color)
    patch.set_alpha(0.7)
    patch.set_edgecolor('black')
    patch.set_linewidth(1.2)

# 设置其他元素的样式
for element in ['whiskers', 'caps', 'medians']:
    for item in box_plot[element]:
        item.set_color('black')
        item.set_linewidth(1.2)

# 计算中位数并绘制趋势线
medians = [np.median(data_dict[temp]) for temp in temperatures]
ax.plot(temperatures, medians, 'k--', linewidth=2, alpha=0.7, label='中位数趋势')

# 设置坐标轴
ax.set_xlim(-0.05, 1.05)
ax.set_ylim(90, 100)
ax.set_xlabel('Temperature', fontsize=14, fontweight='bold')
ax.set_ylabel('Accuracy (%)', fontsize=14, fontweight='bold')

# 设置x轴刻度
ax.set_xticks(temperatures)
ax.set_xticklabels([str(temp) for temp in temperatures])

# 设置y轴刻度
ax.set_yticks(range(90, 101, 1))

# 添加网格
ax.grid(True, alpha=0.3)
ax.set_axisbelow(True)

# 设置标题
ax.set_title('Temperature vs Accuracy Distribution', fontsize=16, fontweight='bold', pad=20)

# 不显示图例

# 调整布局
plt.tight_layout()

# 显示图形
plt.show()

# 打印数据统计信息
print("数据统计信息:")
print("=" * 50)
for temp in temperatures:
    data = data_dict[temp]
    print(f"Temperature {temp}:")
    print(f"  样本数: {len(data)}")
    print(f"  均值: {np.mean(data):.2f}%")
    print(f"  中位数: {np.median(data):.2f}%")
    print(f"  标准差: {np.std(data):.2f}%")
    print(f"  范围: {min(data):.2f}% - {max(data):.2f}%")
    print()

# 可选: 保存图像
# plt.savefig('temperature_accuracy_boxplot.png', dpi=300, bbox_inches='tight')
print("图表已生成完成！")