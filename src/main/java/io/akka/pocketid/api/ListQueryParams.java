package io.akka.pocketid.api;

import akka.javasdk.http.RequestContext;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.regex.Pattern;

/** Reads the same {@code search}/{@code sort[column]}/{@code sort[direction]}/
 * {@code pagination[page]}/{@code pagination[limit]}/{@code filters[field][i]} query parameters
 * the vendored frontend's {@code ListRequestOptions} (list-request.type.ts) already sends on
 * every admin list request, mirroring internal/utils/list_request_util.go's ListRequestOptions
 * on the source side. A view query in this SDK cannot take a client-supplied sort column or an
 * arbitrary LIKE/IN predicate, so the view is asked for its full unfiltered set and this class
 * applies search, filters, sort and paging to that list before it is wrapped for the response. */
final class ListQueryParams {
  private static final Pattern FILTER_KEY = Pattern.compile("^filters\\[([^\\]]+)\\]\\[\\d+\\]$");

  final String search;
  final String sortColumn;
  final String sortDirection;
  final int page;
  final int limit;
  final Map<String, List<String>> filters;

  private ListQueryParams(
      String search, String sortColumn, String sortDirection, int page, int limit, Map<String, List<String>> filters) {
    this.search = search;
    this.sortColumn = sortColumn;
    this.sortDirection = sortDirection;
    this.page = page;
    this.limit = limit;
    this.filters = filters;
  }

  static ListQueryParams from(RequestContext ctx) {
    var q = ctx.queryParams();
    String search = q.getString("search").map(String::trim).filter(s -> !s.isEmpty()).orElse(null);
    String sortColumn = q.getString("sort[column]").filter(s -> !s.isBlank()).orElse(null);
    String sortDirection = q.getString("sort[direction]").filter(s -> !s.isBlank()).orElse("asc");
    int page = q.getInteger("pagination[page]").orElse(0);
    int limit = q.getInteger("pagination[limit]").orElse(0);

    Map<String, List<String>> filters = new LinkedHashMap<>();
    for (var entry : q.toMultiMap().entrySet()) {
      var matcher = FILTER_KEY.matcher(entry.getKey());
      if (matcher.matches()) {
        filters.computeIfAbsent(matcher.group(1), k -> new java.util.ArrayList<>()).addAll(entry.getValue());
      }
    }
    return new ListQueryParams(search, sortColumn, sortDirection, page, limit, filters);
  }

  /** @param searchPredicate matched against {@code search} when present; ignored otherwise.
   *  @param sortableColumns comparators keyed by the frontend's column name (list-request.type.ts). */
  <T> Dtos.Page<T> apply(List<T> items, Predicate<T> searchPredicate, Map<String, Comparator<T>> sortableColumns) {
    return apply(items, searchPredicate, sortableColumns, Map.of());
  }

  /** @param filterableFields renders a field to the string a {@code filters[field][i]} value is
   *  compared against (case-insensitively) — an item passes a field's filter if any requested
   *  value for that field matches, and passes overall if every requested field matches (AND
   *  across fields, OR within one field's value list — the same semantics as the source's
   *  {@code WHERE col IN (...)}). A field the frontend sent no filter for is not constrained. */
  <T> Dtos.Page<T> apply(
      List<T> items, Predicate<T> searchPredicate, Map<String, Comparator<T>> sortableColumns,
      Map<String, Function<T, String>> filterableFields) {
    List<T> filtered = search == null ? items : items.stream().filter(searchPredicate).toList();

    if (!filters.isEmpty()) {
      filtered = filtered.stream().filter(item -> filters.entrySet().stream().allMatch(f -> {
        var extractor = filterableFields.get(f.getKey());
        if (extractor == null) return true;
        String actual = extractor.apply(item);
        return f.getValue().stream().anyMatch(v -> v.equalsIgnoreCase(actual));
      })).toList();
    }

    List<T> sorted = filtered;
    if (sortColumn != null && sortableColumns.containsKey(sortColumn)) {
      Comparator<T> cmp = sortableColumns.get(sortColumn);
      if ("desc".equalsIgnoreCase(sortDirection)) cmp = cmp.reversed();
      sorted = filtered.stream().sorted(cmp).toList();
    }

    int totalItems = sorted.size();
    boolean paging = page > 0 && limit > 0;
    int effectiveLimit = paging ? limit : Math.max(totalItems, 1);
    int totalPages = Math.max((int) Math.ceil(totalItems / (double) effectiveLimit), 1);
    int currentPage = paging ? Math.min(page, totalPages) : 1;

    List<T> pageItems = sorted;
    if (paging) {
      int from = Math.min((currentPage - 1) * limit, totalItems);
      int to = Math.min(from + limit, totalItems);
      pageItems = sorted.subList(from, to);
    }

    return new Dtos.Page<>(pageItems, new Dtos.Pagination(totalItems, totalPages, currentPage, effectiveLimit));
  }
}
