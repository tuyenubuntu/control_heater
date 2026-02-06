from PySide6.QtWidgets import QWidget, QVBoxLayout
from PySide6.QtCore import Qt
import matplotlib.pyplot as plt
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure
import numpy as np
from collections import deque


class HistogramUI:
    """Biểu đồ theo dõi nhiệt độ PV thực tế so với Setpoint"""
    
    def __init__(self, parent_widget: QWidget = None, max_samples: int = 500):
        """
        parent_widget: QWidget cha để nhúng biểu đồ
        max_samples: số lượng mẫu lưu trữ tối đa
        """
        self.max_samples = max_samples
        self.pv_samples = deque(maxlen=max_samples)
        self.sp = None
        self.sample_count = 0
        
        # Setup matplotlib figure - fit 271x135px label, fill hết
        # DPI cao hơn để sharp, size lớn để fill
        self.fig = Figure(figsize=(4, 2.2), dpi=100)
        self.ax = self.fig.add_subplot(111)
        # Tight margins so the plot fills the parent label/widget
        # Keep a bit more left/bottom room for tick labels and axis-unit text
        self.fig.subplots_adjust(left=0.09, right=0.98, top=0.95, bottom=0.09)
        self.canvas = FigureCanvas(self.fig)
        
        # Layout
        if parent_widget:
            self.layout = QVBoxLayout(parent_widget)
            self.layout.addWidget(self.canvas)
            self.layout.setContentsMargins(0, 0, 0, 0)
            parent_widget.setLayout(self.layout)

    def add_pv_sample(self, pv: float):
        """Thêm một mẫu PV vào biểu đồ"""
        if pv is not None:
            self.pv_samples.append(pv)
            self.sample_count += 1

    def set_setpoint(self, sp: float):
        """Cập nhật setpoint"""
        self.sp = sp

    def update_histogram(self, sp: float = None):
        """Vẽ/cập nhật biểu đồ line chart"""
        if sp is not None:
            self.sp = sp
        
        self.ax.clear()
        
        if len(self.pv_samples) == 0:
            # Cleaner placeholder: keep axes visible, subtle grid and light message
            self.ax.set_facecolor('white')
            self.ax.grid(True, alpha=0.12, linewidth=0.4)
            self.ax.tick_params(labelsize=6, colors='#333333', pad=2)
            # If a setpoint exists, show faint SP band so user sees context
            if self.sp is not None:
                target_range = 2.0
                # use very faint coloring for placeholder
                self.ax.fill_between([0, 1], self.sp - target_range, self.sp + target_range,
                                     color='green', alpha=0.06, transform=self.ax.get_xaxis_transform())
                self.ax.axhline(self.sp, color='red', linestyle='--', linewidth=0.6, alpha=0.5)
            # Centered subtle message
            self.ax.text(0.5, 0.5, "Chưa có dữ liệu", ha='center', va='center',
                         transform=self.ax.transAxes, fontsize=7, color='#808080')
            # reasonable empty ranges so axes show up but don't waste space
            self.ax.set_xlim(0, 10)
            self.ax.set_ylim(20, 80)
            self.canvas.draw()
            return
        
        pv_list = list(self.pv_samples)
        x_data = np.arange(len(pv_list))
        
        # Vẽ vùng target setpoint (±2°C)
        if self.sp is not None:
            target_range = 2.0
            self.ax.fill_between(x_data, self.sp - target_range, self.sp + target_range, 
                                alpha=0.15, color='green', label='Target ±2°C')
        
        # Vẽ đường PV (xanh dương)
        self.ax.plot(x_data, pv_list, color='steelblue', linewidth=0.8, label='PV', marker='o', markersize=0.2)
        
        # Vẽ vạch setpoint (đỏ nét đứt)
        if self.sp is not None:
            self.ax.axhline(self.sp, color='red', linestyle='--', linewidth=0.8, label=f'SP={self.sp:.1f}°C')
        
        # Tính và hiển thị mean
        mean_pv = np.mean(pv_list)
        self.ax.axhline(mean_pv, color='orange', linestyle=':', linewidth=0.6, alpha=0.7, label=f'Mean={mean_pv:.1f}°C')
        
        # Labels và grid (no title so chart uses full area)
        self.ax.set_xlabel('')
        self.ax.set_ylabel('')
        self.ax.grid(True, alpha=0.2, linewidth=0.3)
        self.ax.legend(loc='upper right', fontsize=6, framealpha=0.8, edgecolor='none')
        # Ensure tick labels are visible and have a readable color/padding
        self.ax.tick_params(labelsize=6, colors='#333333', pad=2)
        self.ax.yaxis.set_tick_params(labelleft=True)
        
        # Axis unit labels: will be placed at axis edges after limits set below
        
        # Format y-axis
        if len(pv_list) > 0:
            y_min = min(pv_list) - 5
            y_max = max(pv_list) + 5
            if self.sp is not None:
                y_min = min(y_min, self.sp - 10)
                y_max = max(y_max, self.sp + 10)
            self.ax.set_ylim(y_min, y_max)
        
        # Place axis unit labels at axis edges (using axes coordinates)
        # X-axis: 'ms' at bottom-right (end of X axis, under the plot)
        self.ax.text(1.0, -0.07, 'ms', fontsize=6, ha='right', va='top', style='italic', transform=self.ax.transAxes)
        # Y-axis: '°C' at top-left (end of Y axis, left side of the plot)
        self.ax.text(-0.07, 1.01, '°C', fontsize=6, ha='left', va='bottom', style='italic', transform=self.ax.transAxes)

        self.canvas.draw()

    def get_stats(self) -> dict:
        """Thống kê: mean, std, min, max"""
        if len(self.pv_samples) == 0:
            return {}
        
        pv_list = list(self.pv_samples)
        return {
            'mean': np.mean(pv_list),
            'std': np.std(pv_list),
            'min': np.min(pv_list),
            'max': np.max(pv_list),
            'count': len(pv_list),
        }

    def clear(self):
        """Xóa toàn bộ dữ liệu"""
        self.pv_samples.clear()
        self.sp = None
        self.sample_count = 0
        self.ax.clear()
        self.canvas.draw()

