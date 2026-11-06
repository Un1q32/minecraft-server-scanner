package com.mcdbbrowser;

/** Zoom/pan state for the activity time axis. */
final class ChartView {
	private static final double MIN_SPAN_SECONDS = 60.0;

	private double fullStart;
	private double fullEnd;
	private double start;
	private double end;
	private boolean dragging;
	private double dragStartX;
	private double dragStart;
	private double dragEnd;

	void reset(double[] range) {
		this.fullStart = range[0];
		this.fullEnd = range[1];
		this.start = this.fullStart;
		this.end = this.fullEnd;
		this.dragging = false;
	}

	double start() {
		return this.start;
	}

	double end() {
		return this.end;
	}

	boolean hasRange() {
		return this.end > this.start;
	}

	boolean isZoomed() {
		return this.hasRange() && (this.start > this.fullStart + 0.5 || this.end < this.fullEnd - 0.5);
	}

	boolean scroll(double mouseX, double scrollY, int left, int right) {
		if (!this.hasRange() || scrollY == 0.0 || right <= left) {
			return false;
		}
		double span = this.end - this.start;
		double fullSpan = this.fullEnd - this.fullStart;
		double minSpan = Math.min(MIN_SPAN_SECONDS, fullSpan);
		double factor = scrollY > 0.0 ? 0.8 : 1.25;
		double newSpan = Math.max(minSpan, Math.min(fullSpan, span * factor));
		if (newSpan >= fullSpan) {
			this.start = this.fullStart;
			this.end = this.fullEnd;
			return true;
		}
		double time = this.timeAt(mouseX, left, right);
		double ratio = (time - this.start) / span;
		double newStart = time - ratio * newSpan;
		double newEnd = newStart + newSpan;
		if (newStart < this.fullStart) {
			newStart = this.fullStart;
			newEnd = newStart + newSpan;
		}
		if (newEnd > this.fullEnd) {
			newEnd = this.fullEnd;
			newStart = newEnd - newSpan;
		}
		this.start = newStart;
		this.end = newEnd;
		return true;
	}

	boolean press(double mouseX) {
		if (!this.hasRange()) {
			return false;
		}
		this.dragging = true;
		this.dragStartX = mouseX;
		this.dragStart = this.start;
		this.dragEnd = this.end;
		return true;
	}

	void drag(double mouseX, int left, int right) {
		if (!this.dragging || right <= left) {
			return;
		}
		double span = this.dragEnd - this.dragStart;
		double delta = (mouseX - this.dragStartX) * span / (right - left);
		double newStart = this.dragStart - delta;
		double newEnd = this.dragEnd - delta;
		if (newStart < this.fullStart) {
			newStart = this.fullStart;
			newEnd = newStart + span;
		}
		if (newEnd > this.fullEnd) {
			newEnd = this.fullEnd;
			newStart = newEnd - span;
		}
		this.start = newStart;
		this.end = newEnd;
	}

	void release() {
		this.dragging = false;
	}

	boolean isDragging() {
		return this.dragging;
	}

	private double timeAt(double mouseX, int left, int right) {
		double ratio = Math.max(0.0, Math.min(1.0, (mouseX - left) / (double) (right - left)));
		return this.start + ratio * (this.end - this.start);
	}
}
