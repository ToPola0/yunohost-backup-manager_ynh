"""Self-contained five-field cron evaluator used only by YunoHost Backup Manager.

No system crontab modifications; all jobs run inside this app process.
Five fields: minute (0-59), hour (0-23), day (1-31), month (1-12), weekday (0/7 Sunday).
Accepted field syntax: *, n, a-b, */step, a-b/step, n/step, comma lists.
Cron's traditional OR semantics are used when both day and weekday are constrained.
"""
from datetime import datetime, timedelta
import re


class CronSpec:
    __slots__ = ('expression', 'fields', 'any_dom', 'any_dow')

    def __init__(self, expression):
        if not isinstance(expression, str) or len(expression) > 120:
            raise ValueError('Podaj pięć pól cron o długości do 120 znaków.')
        pieces = expression.split()
        if len(pieces) != 5:
            raise ValueError('Cron wymaga dokładnie pięciu pól: min godz dzień miesiąc dzień_tygodnia.')
        limits = [(0, 59), (0, 23), (1, 31), (1, 12), (0, 7)]
        self.fields = tuple(self._field(piece, low, high) for piece, (low, high) in zip(pieces, limits))
        self.expression = expression
        # Treat 7 as Sunday; 0 and 7 are equivalent.
        self.fields = self.fields[:4] + (frozenset(0 if v == 7 else v for v in self.fields[4]),)
        self.any_dom = self.fields[2] == frozenset(range(1, 32))
        self.any_dow = self.fields[4] == frozenset(range(7))

    @staticmethod
    def _field(raw, low, high):
        result = set()
        for piece in raw.split(','):
            if not piece:
                raise ValueError('Niepoprawna lista wartości cron.')
            if piece.count('/') > 1:
                raise ValueError('Niepoprawny krok cron.')
            term, sep, step_s = piece.partition('/')
            if sep and (not step_s.isdigit() or int(step_s) < 1):
                raise ValueError('Krok cron musi być liczbą dodatnią.')
            step = int(step_s) if sep else 1
            if term == '*':
                start, end = low, high
            elif re.fullmatch(r'\d+-\d+', term):
                first, last = term.split('-')
                start, end = int(first), int(last)
            elif term.isdigit():
                start = int(term)
                end = high if sep else start
            else:
                raise ValueError('Niepoprawna wartość cron: ' + piece)
            if not low <= start <= end <= high:
                raise ValueError('Wartość cron poza zakresem: ' + piece)
            result.update(range(start, end + 1, step))
        return frozenset(result)

    def matches(self, when):
        minute, hour, day, month = when.minute, when.hour, when.day, when.month
        weekday = (when.weekday() + 1) % 7  # Python Monday=0, cron Sunday=0
        if minute not in self.fields[0] or hour not in self.fields[1] or month not in self.fields[3]:
            return False
        dmatch = day in self.fields[2]
        wmatch = weekday in self.fields[4]
        if self.any_dom or self.any_dow:
            return dmatch and wmatch
        return dmatch or wmatch


def next_occurrence(expression, now=None):
    """Calculate next firing in local server timezone, to minute precision."""
    spec = CronSpec(expression)
    now = now or datetime.now().astimezone()
    # Timestamp arithmetic normalizes DST transitions when given an aware instant.
    current = int(now.timestamp() // 60) * 60 + 60
    for _ in range(60 * 24 * 366 * 5):
        # Re-resolve the local offset each time: fixed-offset tzinfo would miss DST.
        when = datetime.fromtimestamp(current).astimezone()
        if spec.matches(when):
            return when
        current += 60
    raise ValueError('Nie udało się wyznaczyć następnego terminu cron.')
